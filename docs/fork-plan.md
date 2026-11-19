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

1. Add `cmd/registry-import` (or `eraser registry sync`). It reads the CPPA
   2026 registry CSV (`cppa.ca.gov/data_broker_registry/registry.csv`) and writes
   `data/brokers.yaml`. Each broker gets:
   `id, name, email, website, opt_out_url, source: ca-cppa-2026, verified_at`.
   - Normalizes `[at]` obfuscation, lowercases, and dedupes.
   - Rejects freemail domains (gmail/outlook/hotmail/yahoo/aol/icloud) unless
     an allowlist names them explicitly.
   - Optional `--check-mx`: drops domains with no MX/A record.
   - verify: unit tests on CSV fixtures (obfuscated email, freemail, duplicate,
     malformed); the generated count is roughly 625 minus rejections.
2. Keep a small hand-curated `data/brokers.manual.yaml` for people-search sites
   that aren't in the registry. Each entry needs a `source_url` that cites the
   broker's own privacy page. An entry with no citation fails to load.
   - verify: a loader test fails on an entry with no citation.
3. Fold in useful data from upstream PR #29 (real bounce reports) as `flagged`
   entries or removals. Re-check each one; don't trust it blind.
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

1. New `options.disclose` setting: which profile fields go into emails. Default:
   name and email only. Address, phone and DOB are opt-in; brokers that need
   them will ask.
   - verify: a template test shows DOB/phone/address are left out by default and
     included when enabled.
2. Add `Date` and `Message-ID` headers, and RFC 2047-encode non-ASCII names in
   the From header.
   - verify: a test parses the generated message with `net/mail`.
3. Support STARTTLS on port 587 alongside implicit TLS on 465.
   - verify: a test against a fake SMTP server (`net/smtp` test pattern).

## Phase 3: Inbox safety (`monitor`, scan, `cleanup-bounces`)

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
6. Make web sends use the configured template, `excluded_brokers` and `regions`.
   Share one send path with the CLI so they can't drift apart.
   - verify: a test shows excluded brokers never reach the sender.
7. The setup wizard merges into the existing config instead of replacing it.
8. Fix the data race on `Job` fields (found in upstream PR #18). Run tests
   with `-race`.
9. Replace `gorilla/csrf` (GO-2025-3884: trusted-origin check is flawed, no fix
   available) with Go's built-in `http.CrossOriginProtection`. Then remove
   the allowlist entry in `scripts/govulncheck.sh`.
   - verify: a cross-origin POST gets a 403 and a same-origin POST succeeds;
     `scripts/govulncheck.sh` passes with an empty allowlist.
10. Make the write timeout fit the long-running handlers (inbox scan, test send).

## Phase 6: CLI behavior

1. `send` asks for confirmation before sending (shows the count and the
   disclosed fields) unless `--yes` is passed. Add `--limit`, and skip brokers
   already sent to within N days (history dedupe).
2. `send` applies the same persisted daily cap as the web UI.
3. `init` hides password input (`golang.org/x/term`) and asks for DOB only if
   it's enabled under `disclose`.
4. `config.Save` sets file permissions to 0600 even when the file already exists.

## Phase 7: Docs and cleanup

1. Make the README match reality: SMTP only (or bring other providers back),
   no automated-send Actions workflow (or a safe one), the real broker count and
   where it comes from, how the data is checked, and a privacy model section.
2. Update CLAUDE.md and `config.example.yaml` to match.
3. Remove dead code: `brokerDB.Save` with 0644, SendGrid/Resend references, and
   unused fields.
4. Add a `SECURITY.md` with the threat model and how to report issues.

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
