# Fork Plan: Hardening Eraser

Fork: `kesmit13/eraser` (origin). Upstream: `digisamroc/eraser` (fetch only;
no merges since the initial commits, 11 open PRs).

Goal: a version you can trust with your personal data. That means sending
the minimum data, only to verified broker addresses, and never acting on
unverified mail or loading third-party code.

Each phase is one branch and one PR into the fork's `main`. Every bug fix starts
with a failing test that reproduces it. Pre-commit must pass before every commit.

---

## Phase 0: Guardrails (do first)

1. Add `.pre-commit-config.yaml`: `gofmt`, `go vet`, `golangci-lint`
   (incl. `gosec`), `gitleaks`, a check that blocks `config.yaml` / `*.db` from
   being committed, and `go test ./...`.
   - verify: `pre-commit run --all-files` passes on a clean tree.
2. Add CI (`.github/workflows/ci.yml`): build, vet, lint, test, `govulncheck`
   (via `scripts/govulncheck.sh`, which allows specific known issues).
   Runs only on push and PR. No secrets, and it never sends mail.
   - verify: green run on the fork.
3. Bump dependencies: `golang.org/x/net` (HTML parser DoS bugs), `chromedp`,
   `go-imap`, and the rest. Then run `govulncheck ./...`.
   - verify: `govulncheck` is clean and tests pass.

## Phase 1: Verified broker list (largest privacy win)

Status: done. 625 registry rows produce 598 brokers: 24 merged (shared
email), 1 personal Gmail rejected, 2 domains with no mail host, 15 form-only.

1. Add `cmd/registry-import`. It reads the CPPA registry CSV
   (`cppa.ca.gov/data_broker_registry/registry.csv`) and writes
   `data/brokers.yaml`. Each broker gets `source`, `source_url` and
   `registry_id`.
   - Normalizes `[at]` obfuscation, lowercases, and merges duplicate emails.
     Adds `https://` to bare domains and takes the first site from a list.
   - Rejects personal mailbox domains, with no allowlist.
   - Optional `-check-mx`: drops domains with no MX/A record (honors null MX).
   - verify: unit tests on CSV fixtures (obfuscated email, freemail, duplicate,
     malformed).
2. Keep a small hand-curated `data/brokers.manual.yaml` (add / overrides /
   exclude), applied when the list is generated. Every entry needs an https
   `source_url`. An entry with no citation fails the build.
   - verify: tests fail on entries with no citation.
3. Fold in useful data from upstream PR #29: 15 registry addresses it reports
   as "email not processed" became `form-only` overrides that cite PR #29.
   Only addresses that also appear in the registry were used. The PR's other
   41 flagged addresses aren't in the generated list at all. `send` (CLI and web)
   skips form-only brokers; the web UI shows the form link instead.
4. Load-time checks in `broker.LoadFromFile`: email must parse, no freemail,
   ids unique, region/category from a fixed set.
   - verify: tests for each rejection.
5. Fix region filtering: putting `global` in `regions` should mean "also include
   global brokers", not "include every region".
   - verify: table test for `[us]`, `[us, global]`, `[eu]`, `[]`.
6. Document the refresh process in the README, and add a monthly CI job that
   opens a PR when the registry changes. That job only edits data; it never
   sends mail.

## Phase 2: Send less data

Status: done.

1. New `options.disclose` setting: `location`, `street_address` (which also
   sends location), `phone` and `date_of_birth`. Default: name and email only.
   - Brokers can add fields for themselves only, via `disclose` in a
     `data/brokers.manual.yaml` override (needs a cited source). A broker gets
     the global setting plus its own list.
   - `Render` requires a `config.Disclosure` argument, so no caller can skip it.
   - `send` prints what's sent and what's withheld; dry runs also show per-broker
     extras.
   - No reliable per-broker dataset of verification requirements exists (the
     CPPA registry doesn't record it). 11 CCR § 7062 generally treats matching
     two data points as reasonable, and name plus email are two.
   - verify: template tests for all three templates (default, global,
     per-broker); config and registry tests.
2. Add `Date` and `Message-ID` headers, RFC 2047-encode the From display name,
   and send the body as quoted-printable UTF-8. The real Message-ID is returned
   and stored in history.
   - verify: a fake SMTP server receives the message, and it parses with
     `net/mail` and round-trips non-ASCII text.
3. Support STARTTLS on 587 (the default for any non-465 port) alongside
   implicit TLS on 465, with an optional `tls_mode` override. Fails closed if
   STARTTLS isn't offered. Connections honor the context deadline.
   - verify: fake-server tests for STARTTLS, implicit TLS, a missing STARTTLS,
     an untrusted certificate and a deadline. A mutation test confirms the
     missing-STARTTLS test catches a plaintext fallback.

## Phase 3: Inbox safety (`monitor`, scan, `cleanup-bounces`)

Status: done. All items below, plus:
- Found: `broker_responses` had no `email_body` column, yet every insert
  wrote one. So on any database this code created, **inbox monitoring never
  stored a response** (the web scan ignored the error). A migration adds the
  column. Response timestamps also never parsed; that's fixed with the
  Phase 6 time parser.
- Item 3 went further than planned. Instead of IMAP `FROM` searches (which
  would need ~600 OR terms), fetching is two-pass: envelopes only, then
  `BODY.PEEK[]` bodies only for broker matches. Mailboxes are opened
  read-only (EXAMINE).
- Unauthenticated mail doesn't change pipeline status, and the "Eraser
  test email" shortcut requires authentication. Otherwise a spoofed "your
  data was removed" email could mark a broker done.
- Responses are deduplicated (`inbox.Record`), so scanning twice no longer
  stores everything twice.
- Category ties are resolved in a fixed order (they used to depend on random
  map iteration).
- verify: an in-process IMAP server (go-imap memory backend) with a
  recording wrapper. Reintroducing each bug (no PEEK, bodies for all mail,
  folder-blind archive, trusting a forged lower header, Gmail matching) makes
  a test fail.
- Known limitation: when the server lacks MOVE, archiving falls back to
  COPY + `\Deleted` + EXPUNGE, and a plain EXPUNGE also removes other
  messages already flagged `\Deleted` in that folder. Gmail and Outlook
  support MOVE.

0. Flag broker replies that ask for more identifying information, so the user
   can add a per-broker `disclose` override (Phase 2). Match replies to sent
   requests with `In-Reply-To` against the stored Message-ID, which is stronger
   than sender-domain matching.

1. Never match a freemail domain to a broker. Match by exact domain or a
   subdomain of a registered domain.
   - verify: regression test: `friend@gmail.com` → no broker (currently matches `vror`).
2. Require DKIM/SPF to pass before acting on a broker email. Read the
   `Authentication-Results` header (Gmail adds it). If authentication fails,
   mark the email for review and extract no URLs from it.
   - verify: tests with pass, fail and missing headers.
3. Fetch with read-only `BODY.PEEK[]` so the user's mail isn't marked as read.
   Search with an IMAP `FROM` filter for broker domains instead of downloading
   every recent email.
   - verify: a test asserts the fetch uses `Peek`.
4. Fix the archive bug: only move IDs that came from the folder being moved
   from. Track message IDs per folder.
   - verify: a unit test on the ID-grouping logic.
5. Only store the email body when it's needed for reclassification, and cap it
   at 64 KB.
6. Fix watch mode reprocessing the same emails on every new-mail notification.

## Phase 4: Browser automation (`fill`, `confirm`)

Status: split into two PRs.
- **4A: done.** chromedp v0.9.5 → v0.24 (item 7), item 4, plus a real-Chrome
  test harness (`internal/browser/browser_test.go`; skipped with `-short`,
  required in CI).
  - Found: the browser was started inside the first form's timeout context,
    so it was killed when that form finished. `fill --pending` never handled
    a second form ("context canceled"). It now starts in `New`.
  - Submitting: no `:contains()` selectors and no blind Enter. Only a submit
    control inside a form that has filled fields is clicked. If there's none,
    the result says to submit by hand. (My first version could click an
    unrelated "Delete my account" button on the page; a test now covers that.)
  - Removed unused helpers (GetPageHTML, GetPageTitle, WaitForNavigation,
    EnablePageEvents, FillDropdown, CheckCheckbox, DetectFormFields).
- **4B: done.** Items 1, 2, 3, 5, 6.
  - `broker.OwnsURL` is the one rule for `fill` and `confirm`: https, and the
    host shares an organizational domain with the broker's email or website,
    or the URL is under the broker's registered opt-out URL. Paths are
    normalized first, since `.../abc/../other` used to pass the prefix check.
  - `fill`: the page must pass the check before navigating, after loading
    (catching HTTP and script redirects), after a CAPTCHA wait, and before
    submitting. Inbox links must come from authenticated emails, with no
    override. `--allow-other-domain` applies only to a URL the user typed
    with `--broker`.
  - `confirm`: every redirect hop is checked against the broker.
  - Forms and CAPTCHA helper tasks get only the disclosed profile (global
    plus the broker's own `disclose` list). The broker's pipeline status
    changes only when a form was actually submitted.
  - Screenshots: 0600 files in a 0700 folder; names can't escape it. The
    `/screenshots/{name}` route the task pages already linked to now exists,
    serving only names that match the screenshot pattern.
  - `pipeline.browser_headless` is honored (Load used to force it true);
    `--headless` overrides it only when given.
  - verify: real-Chrome tests (redirects, a disallowed start URL, disclosed
    fields only, screenshot permissions and names), confirm-redirect tests,
    OwnsURL cases including path traversal, route traversal attempts. With
    the post-load check removed, the redirect test shows the whole profile
    being filled on the other site.

1. `fill` gets the same domain check as `confirm`. The form URL host must match
   the broker's registered domain. There is no override when the URL came from
   the inbox; `--url` overrides are only for URLs the user typed.
   - verify: a test shows an off-domain form URL is refused.
2. `confirm` checks every redirect hop against the broker domain, not just the
   first URL.
   - verify: an `httptest` redirect to a foreign host is refused.
3. Only fill fields the form actually requires, and never DOB unless it's
   enabled under `disclose`.
4. Remove the invalid `:contains()` selectors. Stop reporting success after a
   blind Enter key press.
5. Save screenshots with owner-only permissions (0600/0700). Either add the
   missing `/screenshots/` route, behind a path-traversal-safe handler, or
   remove the image display.
6. Respect `browser_headless` from config instead of always forcing it on.
7. Upgrade chromedp from v0.9.5 to v0.24+. It's pinned at v0.9.5 for now
   because v0.24 rewrote its API: `Run` now returns two values and `Evaluate`
   is generic.

## Phase 5: Web UI

Status: split into two PRs.
- **5A (security): done.** Items 1, 2, 3, 9 and 10.
  - The bundled `static/css/tailwind.min.css` turned out to be the Tailwind
    Play CDN *JavaScript* of unknown provenance. It's deleted. CSS is now built
    with the pinned, checksum-verified Tailwind v3.4.19 standalone CLI
    (`scripts/build-css.sh`), and CI fails if `app.css` is stale.
  - Bundled htmx 1.9.10 verified byte-identical to the npm release and loaded
    with SRI. Google Fonts dropped for the system font stack.
  - CSP now has no third parties and no `'unsafe-eval'`. `'unsafe-inline'`
    scripts remain for 27 inline handlers and 11 `<script>` blocks; moving
    those out (or adding nonces) is a follow-up.
  - Saving inbox settings used to wipe folder/archive settings and leave the
    IMAP server and port unset until restart. Fixed.
- **5B (behavior): done.** Items 5, 6, 7 and 8. Item 4 (local access token)
  is deferred: the Host check and cross-origin protection cover the remote
  attacks; it's only needed against other local users or processes.
  - Item 5: job persistence and auto-resume are removed rather than reworked.
    History plus the resend window make them redundant, since "Send all"
    continues where it left off. A leftover `~/.eraser/pending_job.json` is
    deleted on startup.
  - Item 6: `sendplan.ForConfig` (filters, resend window, cap) and
    `sendplan.Deliverer` (render, send, record) are used by the CLI, web
    "Send all", and web single "Send".
  - Item 7: the wizard starts from and merges into the existing config.
    Settings has a "What Gets Sent" section for `options.disclose`. Also
    fixed: on a first visit the profile step didn't save, because it updated
    the session by a cookie the request didn't have yet.
  - Item 8: job fields are only touched under the job lock. `Complete()` no
    longer overwrites a cancelled job's status.
    - verify: race tests that catch a reintroduced unlocked read 5 out of 5
      times.

1. Add a Host header allowlist middleware (`localhost:PORT`, `127.0.0.1:PORT`)
   to block DNS rebinding.
   - verify: a request with `Host: evil.example` gets a 403.
2. Use the bundled local htmx/Tailwind files only. Remove the CDN and Google
   Fonts from the layout and the CSP, and drop `'unsafe-eval'`. (Compare with
   upstream PRs #34 and #18.)
   - verify: grep finds no `https://` in `<script>`/`<link>` tags; a CSP header
     test passes.
3. Never put stored passwords back into pages. Show a "password is set"
   indicator and only update the password when a new one is submitted.
4. Optional local access token: `serve` prints a one-time URL with a token,
   which sets a cookie. This stops other local users and processes from
   reading the UI.
5. Never resume a send job automatically. Show "resume N remaining?" in the UI.
   The daily limit is persisted per calendar day and survives restarts.
   - verify: a test shows a restart on the same day doesn't exceed the limit.
6. Make web sends use the configured template, `excluded_brokers`, `regions`
   and `resend_after_days`. Share one send path with the CLI (build on
   `internal/sendplan`) so they can't drift apart.
   - verify: a test shows excluded brokers never reach the sender.
7. The setup wizard merges into the existing config instead of replacing it.
   Add a disclosure setting to the wizard and settings page. Today
   `options.disclose` is only set by editing the YAML; the web UI always uses
   the safe default, name and email only.
8. Fix the data race on `Job` fields (found in upstream PR #18). Run tests
   with `-race`.
9. Replace `gorilla/csrf` (GO-2025-3884: trusted-origin check is flawed, no fix
   available) with Go's built-in `http.CrossOriginProtection`. Then remove
   the allowlist entry in `scripts/govulncheck.sh`.
   - verify: a cross-origin POST gets a 403 and a same-origin POST succeeds;
     `scripts/govulncheck.sh` passes with an empty allowlist.
10. Make the write timeout fit the long-running handlers (inbox scan, test send).

## Phase 6: CLI behavior

Status: done.

0. Found along the way: `history.GetAllBrokerStatuses` failed whenever any
   history existed (SQLite returns `MAX(sent_at)` as text, which can't be read
   into a time value). The web UI ignored the error, so every broker showed
   "never sent" and "Send all" (default filter: pending) resent to all of
   them. This is likely upstream PR #13. Fixed by parsing times in Go, which
   also compares correctly across time zones.
   - verify: a round-trip test fails on the old code and passes on the new.
1. `send` asks for confirmation (count and disclosed fields), and refuses when
   stdin isn't a terminal unless `--yes` is passed. Added `--limit` and
   `--force-resend`. It skips brokers sent to successfully within
   `options.resend_after_days` (default 30). It stops if a history write
   fails, and Ctrl-C stops between brokers.
2. Daily cap: `options.daily_limit` (default 250) per rolling 24h, counted
   from history, so restarts and mixing CLI and web sends can't exceed it.
   Shared logic lives in `internal/sendplan`; the web job uses the same
   history count.
3. `init` hides the app password. (`init` never asked for DOB, so nothing to
   change there.)
4. `config.Save` chmods an existing file to 0600.

Web "Send all" now applies the same rules (Phase 5B, item 6).

## Phase 7: Docs and cleanup

Status: done.
- README: claims match reality (SMTP only, ~600 registered brokers, no
  unverifiable compliance rates or competitor table). The GitHub Actions
  section is replaced by a local monthly cron, since Actions would put PII
  and mail passwords in repository secrets. There's a new "What Leaves Your
  Computer" table. Clone URLs point to this fork.
- CLAUDE.md rewritten around the invariants each phase established;
  `SECURITY.md` added (threat model, known limitations, reporting).
- `add-broker` and `cleanup-bounces --remove` write `add` / `exclude` entries
  to `data/brokers.manual.yaml` (comments kept) and update
  `data/brokers.yaml`; regeneration then produces the same file. Exclusions
  can cite local `evidence` (a bounce) instead of a URL. `--remove` only acts
  on bounces your provider verified.
- Removed dead code (unused broker DB mutators, classifier helpers, history
  query, `templates/setup.html`), plus the web UI's "750+" and Resend text.
- Lint debt cleared: the whole repo passes golangci-lint, so CI and the
  pre-commit hook lint everything (no changed-lines mode). Real fixes along
  the way: task IDs parse strictly (404 instead of silently becoming task 0),
  and `errors.Is` replaces a `!=` comparison on a context error.

1. Make the README match reality: SMTP only (or bring other providers back),
   no automated-send Actions workflow (or a safe one), the real broker count and
   where it comes from, how the data is checked, and a privacy model section.
2. Update CLAUDE.md and `config.example.yaml` to match.
3. Remove dead code: `brokerDB.Save` with 0644, SendGrid/Resend references, and
   unused fields.
4. Add a `SECURITY.md` with the threat model and how to report issues.
5. `add-broker` and `cleanup-bounces --remove` still write to the generated
   `data/brokers.yaml`, so the next regeneration loses their changes. Make
   them write `add` / `exclude` entries to `data/brokers.manual.yaml` instead.
6. README: note that on Ubuntu 23.10+ Chrome may fail with "No usable
   sandbox". Fix it by allowing user namespaces (see CI) or with Chrome's
   AppArmor profile, never with `--no-sandbox`. (Done in Phase 4B.)

## Phase 8 (optional): Contribute back

Upstream looks inactive. We can still open small, separate PRs to upstream,
e.g. the freemail fix or the registry importer, if you want to.

## Phase 9: Second review (2026-11-19)

A full re-review after Phase 7. Build, vet, `go test -short ./...` and
`scripts/govulncheck.sh` pass. Stages 9A–9F below are one PR each, in this
order: inbox trust first, then local data, sending, watch mode, browser,
registry. As before, every fix starts with a failing test, and every security
fix is checked by reverting it and seeing the test fail.

### 9A: Inbox trust

Status: done. Items 1–4. Notes:
- Reclassify's body backfill also paired a fetched body with the row's old
  flag; it now goes through `inbox.Record` too.
- Bounces are tied to a sent Message-ID from the returned message,
  `In-Reply-To` or `References`. `VerifyBounce` drops the regex recipient
  guess; the report's `Final-Recipient` is checked when present.
- `monitor`, `cleanup-bounces` and the web scans warn when no authserv-id is
  known.
- verify: each fix reverted on its own makes a test fail, except removing
  the explicit `Known()` guard in `Authenticated`, which the authserv-id
  comparison already covers; `TestFetchFailsClosedWithoutAuthServ` catches
  the monitor ignoring its config.

1. **A stored body can come from a different email than its authenticated
   flag.** `inbox.Record` matches by (broker, subject). On a match it
   overwrites type, URLs and `authenticated`, but keeps the old body if one
   was stored. Reclassify then extracts links from that body under the new
   flag. Reproduced: a spoofed email followed by an authenticated one with
   the same subject leaves `authenticated=true` with the spoofed body, and
   reclassify yields the spoofed confirm URL. The same bug affects real mail:
   "Re: Personal Data Removal Request" received, then completed, keeps the
   first body, so reclassify can move a broker back from confirmed to pending.
   - Fix: add a `message_id` column (migration) and match on Message-ID when
     present. Whenever a row is updated, replace body, classification, URLs
     and `authenticated` together, so they always come from one email.
   - verify: the spoofed-then-real test above (fails today); a
     "received" then "completed" test keeps "completed" after reclassify;
     two emails with the same subject but different Message-IDs give two rows.
2. **`cleanup-bounces --remove` trusts any sender that authenticates its own
   domain.** `mailer-daemon@attacker.example` with valid DMARC and a body
   naming `privacy@broker.com` passes, and the broker is excluded for good.
   - Fix: a bounce counts only if it references a Message-ID we sent (from
     the DSN's `message/rfc822` or `text/rfc822-headers` part, or
     `In-Reply-To`/`References`) and the bounced address is the broker we sent
     that message to. `parseBody` must keep those parts. Still require
     `Authenticated`.
   - verify: the forged bounce above → no exclusion; a real Gmail DSN fixture
     that names a sent Message-ID → exclusion; a DSN that names a sent
     Message-ID but a different broker address → no exclusion.
3. **The `Authentication-Results` header's authserv-id is never checked.**
   If the provider adds no such header, the topmost one is whatever the
   sender wrote.
   - Fix: accept only a header whose authserv-id matches the provider
     (`mx.google.com` for Gmail; a new `inbox.authserv_id` setting otherwise).
     Microsoft's header has no authserv-id, so for `provider: outlook` accept
     the topmost header without one. For `provider: imap` without
     `authserv_id`, treat all mail as unauthenticated and say so once.
   - Document the dependency in `SECURITY.md` under known limitations.
   - verify: a forged `Authentication-Results: attacker.example; dmarc=pass`
     as the only header → unauthenticated; Gmail and Outlook fixtures still
     pass.
4. Remove the "test email" shortcut in `ClassifyResponse`. Test emails go to
   the user's own address and never match a broker, so the shortcut only
   lets broker mail containing "this is a test email" mark a broker
   confirmed.
   - verify: an authenticated broker email with that phrase isn't
     classified as success.

### 9B: Local data permissions

Status: done. Items 1 and 2. `config.PrepareDir` is the one place that
creates and tightens `~/.eraser`; folders from `--config` or `--db` are left
as they are. SQLite gives journal files the database file's mode, so a 0600
database keeps them 0600 too.
- verify: new and existing (0644 in a 0755 `~/.eraser`) databases end up
  0600/0700; a hard link to the old config keeps its old contents after
  `Save` (it used to be rewritten in place). Each fix reverted on its own
  makes a test fail.

1. **`history.db` is created 0644.** `NewStore` only sets 0700 on a directory
   it creates; an existing `~/.eraser` keeps its mode, so names and broker
   email bodies can be world-readable.
   - Fix: create the database file 0600 before SQLite opens it, tighten an
     existing file and any `-journal`/`-wal`/`-shm` files to 0600, and chmod
     `~/.eraser` to 0700 (only that directory, not arbitrary parent dirs of a
     `--db` path).
   - verify: a new store → 0600 file; an existing 0644 file in a 0755
     `~/.eraser` → 0600/0700 after `NewStore`.
2. `config.Save` writes in place: a crash leaves a truncated config, and an
   existing 0644 file holds the new contents before the chmod. Write to a
   0600 temp file in the same directory and rename.
   - verify: saving over a 0644 file never exposes contents with 0644 (the
     temp file is 0600 from creation); the result is 0600.

### 9C: Sending

Status: done. Items 1–4. Notes:
- Item 1: an atomic create-if-idle wasn't enough. A request that planned
  before an earlier job finished could still start afterwards with that
  stale plan. `Server.sendMu` now covers "no job running, plan, start" for
  "Send all" and the whole of a single "Send" (so double-clicking "Send" can't
  send twice either). Reproduced first: 8 concurrent requests started 3 jobs.
- Item 4: sender, recipient and DATA rejections keep the reply code and up
  to 200 characters of the server's text; other errors stay generic.
- verify: each fix reverted on its own makes a test fail (7/7); the
  concurrency tests pass 10/10 under `-race`.

1. **Two "Send all" requests can start two jobs.** `GetActive` and `Create`
   are separate steps, and the rate limit allows 30 per minute. Both jobs
   plan from the same history: every broker gets two emails and the daily
   cap can be exceeded up to 2×.
   - Fix: `JobManager.CreateIfIdle` checks and creates under one lock. Also
     refuse a single "Send" for a broker while a job is running.
   - verify: N concurrent POSTs with a counting fake sender → one job, each
     broker sent once (run with `-race`).
2. **An accepted message can be recorded as failed.** If `client.Quit()`
   fails after `DATA` was accepted, `deliver` returns an error, so the next
   run resends.
   - Fix: once the `DATA` reply is 250, ignore the `QUIT` result.
   - verify: a fake server that drops the connection on `QUIT` → success,
     recorded as sent.
3. `use_tls: false` (or leaving it out) sends personal data in plaintext
   whenever there's no username. `Validate` rejects it unless the host is
   loopback.
   - verify: config tests for `smtp.example.com` (rejected) and
     `127.0.0.1` (allowed).
4. `sanitizeSMTPError` reports a recipient rejection as "check your
   configuration". Keep the stage and reply code ("recipient rejected (550)")
   for `RCPT`/`DATA` errors; keep hiding auth details.
   - verify: a fake server rejecting `RCPT` with 550 → that text in the
     history record.

### 9D: Watch mode

Status: done. Items 1 and 2, plus three bugs found while testing:
- The deadlock is real: a test pushing EXISTS + RECENT during IDLE (the
  test backend now implements go-imap's `BackendUpdater`) never got the
  first message with the old code.
- Draining the channel exposed a busy loop: go-imap also reports our own
  SELECT's EXISTS/RECENT as updates, so re-selecting on each fetch looked
  like new mail, forever. The monitor now remembers the folder it has open
  read-only and doesn't re-select it.
- Duplicate delivery: the next UID came from the SELECT snapshot, so a
  message arriving between SELECT and SEARCH was delivered twice. It now
  starts after the highest UID the search returned.
- If IDLE ever ended without an error, the old loop never restarted it and
  the next notification hung. It now restarts IDLE (not covered by a test:
  go-imap's client only returns from IDLE when asked to).
- go-imap's test server has its own race (pushing updates vs. a SELECT in
  progress); the watch test opens the folder before watching to avoid it.
- verify: watch delivers three messages once each and stays idle in
  between; `Connect` returns at its deadline against a silent server; a
  message added mid-fetch isn't returned again. 20/20 under `-race`. The
  old `WatchForNewEmails` and `Connect`, and each other fix reverted, make
  a test fail.

1. **`monitor --watch` will probably deadlock.** go-imap v1 blocks on every
   send to `client.Updates`; `WatchForNewEmails` stops reading the channel
   while IDLE shuts down and while it fetches. Servers commonly send two
   notices per new message (EXISTS then RECENT), so the reader stalls. Found
   by reading go-imap's source; not reproduced yet.
   - Fix: drain `Updates` in its own goroutine for the life of the watch, and
     turn mailbox updates into a non-blocking "new mail" signal (a channel
     with a buffer of 1).
   - verify: a scripted IMAP server (or the memory backend, if it pushes
     IDLE updates) sends EXISTS + RECENT, then another EXISTS during the
     fetch; the watch delivers both messages and stops cleanly on cancel,
     under a test timeout.
2. `Monitor.Connect` ignores its context. Dial with `tls.Dialer.DialContext`
   and wrap with `client.New`, so a slow server can't hang a web scan past
   its timeout.
   - verify: connecting to a listener that never answers returns when the
     context expires.

### 9E: Browser form filling

1. **A later field can overwrite an earlier one.** The filler doesn't track
   filled elements. With `street_address` disclosed, the address selectors
   (`input[placeholder*='address' i]`, `input[name*='address']`) match a
   typical "Email address" field, which is then cleared and filled with the
   street address. Found by reading the selectors.
   - Fix: mark each filled element (`data-eraser-filled`) and skip marked
     elements in both the selector and pattern passes. Run the existence
     check and the fill against the same element.
   - verify: real-Chrome test with an "Email address" field before a street
     address field → each gets its own value.
2. The URL check and the fill are separate steps; a script redirect between
   them gets the profile typed into another site. Pass the allowed origin
   into each field's fill and have the page-side code refuse when
   `location.origin` differs. Low priority; the window is short.
   - verify: real-Chrome test with a page that navigates away on a timer
     → nothing filled on the second site.
3. `GET /tasks/{id}/helper` marks the task opened, and cross-origin
   protection doesn't cover GET. Move the update to a POST the page sends
   on load.
   - verify: a cross-site GET leaves `opened_at` unset.

### 9F: Registry data

1. **Typo and unregistered domains are trusted.** `OwnsURL` trusts a broker's
   website and opt-out hosts, and the web UI links to opt-out URLs. Five
   don't resolve today, four of them registry typos: `www.predactiv.cm`
   (sharethis), `www.mobiityglobal.com` (r-l-polk), `peopesearcher.cm`
   (the-people-searchers), `www360mediadirect.com` (subdirect), plus
   `www.kontextdata.com` (kontext-data). Anyone could register them.
   - Fix: `-check-mx` also resolves website and opt-out hosts and drops
     URLs that don't resolve (reported in the summary, like dropped emails).
     Regenerate `data/brokers.yaml`.
   - verify: a fixture test where an unresolvable website/opt-out host is
     dropped; the regenerated file contains none of the five.
2. Remove `pipeline.auto_confirm` and `pipeline.auto_fill_forms`. Nothing reads
   them, so setting them suggests automation that doesn't exist. Old configs
   still load (unknown keys are ignored).
   - verify: `rg auto_confirm` finds nothing outside the plan.

### Decisions (2026-11-19)

- 9A.3: `provider: imap` without `authserv_id` fails closed: all mail is
  treated as unauthenticated.
- 9C.3: plaintext SMTP to a non-loopback host is rejected outright.

---

## Decisions (2026-11-18)

- **`monitor`/`fill`/`confirm`:** keep them and harden fully (all of Phases 3–4).
  Until Phase 3 lands, they print a warning and need `--i-understand-the-risk`.
- **Web UI:** keep it and harden it (all of Phase 5).
- **Registry scope:** California CPPA registry only.
- **Upstream PRs:** still open. Decide in Phase 8.

## Order

0 → 1 → 2 → 6 → 5 → 3 → 4 → 7. Phases 0–2 plus 6 give a trustworthy
CLI `send` first. The web UI and automation follow.

Phase 9: 9A → 9B → 9C → 9D → 9E → 9F.
