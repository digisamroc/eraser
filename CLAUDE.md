# CLAUDE.md

## Project Overview

Eraser sends data removal requests (generic, CCPA, or GDPR emails) to the data
brokers registered with California's CPPA (~600), tracks replies, and helps
with follow-up forms and confirmation links. It runs locally (CLI and a
localhost web UI) and is built to handle the user's personal data carefully.
This is a hardened fork; `docs/fork-plan.md` records what changed and why.

## Tech Stack

- Go (version and toolchain pinned in `go.mod`)
- CLI: Cobra. Web UI: chi + html/template + htmx 1.9.10 + prebuilt Tailwind CSS
- Email: SMTP only (implicit TLS on 465, STARTTLS otherwise; plaintext only to a loopback relay)
- Storage: SQLite via `modernc.org/sqlite` (`~/.eraser/history.db`)
- Inbox: IMAP via `go-imap` v1. Browser automation: chromedp (headless Chrome)

## Project Structure

```
cmd/eraser/            CLI: all commands (send, serve, monitor, fill, confirm, ...)
cmd/registry-import/   Regenerates data/brokers.yaml from the CPPA registry
internal/broker/       Broker type, validation, FilterList, OwnsURL
internal/browser/      chromedp form filling, CAPTCHA detection, confirmation links
internal/config/       Config, disclosure (what fields leave the machine)
internal/email/        SMTP sender
internal/history/      SQLite: sends, broker replies, pending tasks
internal/inbox/        IMAP fetch, sender authentication, classification, Record
internal/registry/     CPPA CSV parsing, manual overlay, WriteDatabase
internal/sendplan/     Shared send rules (ForConfig) and Deliverer
internal/template/     Email templates (embedded *.tmpl)
internal/web/          Web UI server, templates, static assets
data/brokers.yaml      GENERATED; never edit by hand
data/brokers.manual.yaml  Hand-maintained add / overrides / exclude
scripts/               build-css.sh, govulncheck.sh
```

## Invariants (keep these)

Each of these closes a real bug or leak. Tests cover them.

- **Disclosure:** `template.Engine.Render` requires a `config.Disclosure`.
  Only name and email are always sent; other fields need `options.disclose`
  or the broker's own `disclose` list. Forms filled by `fill` get the same
  filtered profile.
- **One send path:** CLI `send`, web "Send all" and web "Send" all use
  `sendplan.ForConfig` (regions, exclusions, form-only, resend window, daily
  cap from history) and `sendplan.Deliverer.Deliver`. Don't add another.
  If writing history fails, stop: an unrecorded send would be repeated.
  The web handlers hold `Server.sendMu` across "no job running, plan, start
  or send", so two requests never plan from the same history. Once the
  server accepts DATA, the send succeeded (a failed QUIT is ignored).
- **Broker data:** `broker.LoadFromFile` validates every entry (single bare
  email, no personal-mailbox domains, unique ids). Manual entries need an
  https `source_url` (exclusions may use `evidence` instead).
- **Inbox:** fetch envelopes first, then `BODY.PEEK[]` bodies only for broker
  matches; open mailboxes read-only. `Email.Authenticated` comes from the
  topmost `Authentication-Results` header only, and only if it carries the
  provider's authserv-id (`inbox.AuthServFor`; unknown provider = nothing
  authenticated). DMARC, or aligned DKIM. Unauthenticated mail yields no URLs
  and doesn't change pipeline status. Store responses with `inbox.Record`,
  which replaces a row in full (body, links and flag from one email).
  Bounces count only via `inbox.VerifyBounce` (refers to a sent Message-ID).
  UIDs are per-folder. go-imap blocks its connection until each update is
  read: in watch mode one goroutine drains `client.Updates` for the whole
  session, and a fetch only re-EXAMINEs when the folder changes (SELECT
  replies would otherwise look like new mail). `Connect` honors its ctx.
- **fill/confirm:** pages must pass `broker.OwnsURL` (https, broker's
  organizational domain or under its registered opt-out URL). `fill` checks
  before navigating, after load, after CAPTCHA waits and before submitting.
  `confirm` checks every redirect hop. Each field is filled by one in-page
  script that first checks the page is still on the checked origin, skips
  fields already filled (`data-eraser-filled`) and marks the one it fills.
  Only click a submit control inside a form with fields we filled; never
  report a submit that didn't happen.
- **Web UI:** listens on 127.0.0.1; Host header must be `localhost:PORT` or
  `127.0.0.1:PORT` (DNS rebinding); `http.CrossOriginProtection` guards
  state-changing requests, so GET handlers must never change state; never
  render stored passwords; no third-party assets (the CSP forbids them).
  No inline scripts, `on*=` handlers or `javascript:` URLs, in templates or
  Go-built fragments (`script-src 'self'`): page behavior lives in
  `static/js/app.js`, wired with `data-action` attributes.
- **Files:** config and `history.db` 0600 (config saved via temp file and
  rename; the database file is created 0600 before SQLite opens it);
  `~/.eraser` tightened to 0700 by `config.PrepareDir`; screenshots 0700/0600.
- **Chrome sandbox:** never pass `--no-sandbox`.

## Common Commands

```bash
go build -o eraser ./cmd/eraser
go test -short ./...          # fast; skips real-Chrome tests (pre-commit uses this)
go test -race ./...           # everything, as CI runs it (needs Chrome)
golangci-lint run             # whole repo; it has no lint debt
scripts/govulncheck.sh        # fails on any reachable vulnerability
scripts/build-css.sh          # after changing Tailwind classes in templates or web/*.go
go run ./cmd/registry-import -check-mx   # regenerate data/brokers.yaml
./eraser send --dry-run
./eraser serve --port 8080
```

## Working Here

- One branch and PR per change; pre-commit must pass on every commit
  (`pre-commit install`).
- Write the failing test first. For security fixes, also check that the test
  fails when the fix is reverted.
- Brokers: add or correct entries in `data/brokers.manual.yaml` (or use
  `eraser add-broker`), then regenerate. Never hand-edit `data/brokers.yaml`.
- Wrap errors with context: `fmt.Errorf("context: %w", err)`.
- If this checkout is reached through a symlink (e.g. `~/src` ->
  `~/Dropbox/src`), tools that compare `$PWD` with git's top-level path can
  misbehave; run them from `$(pwd -P)`.

## Configuration

`~/.eraser/config.yaml` (see `config.example.yaml`): `profile`, `email`
(SMTP), `options` (template, `disclose`, `daily_limit`, `resend_after_days`,
regions, `excluded_brokers`), `inbox` (IMAP, optional), `pipeline` (browser
settings, optional).
