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

Not done here (Phase 5, item 6): web "Send all" doesn't apply the
resend-after rule yet. Its default "pending" filter only targets never-sent
brokers, but choosing the "sent" filter can resend. Moving it onto
`sendplan` fixes that.

## Phase 7: Docs and cleanup

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

## Phase 8 (optional): Contribute back

Upstream looks inactive. We can still open small, separate PRs to upstream,
e.g. the freemail fix or the registry importer, if you want to.

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
