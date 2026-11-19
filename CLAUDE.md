# CLAUDE.md

## Project Overview

Eraser is an open-source CLI tool that automatically sends data removal requests to data brokers. It's a free alternative to paid services like Incogni and DeleteMe. Users provide their personal information, and the tool sends GDPR, CCPA, or generic removal request emails to the data brokers registered with California (~600).

## Tech Stack

- **Language**: Go 1.21+
- **CLI Framework**: Cobra (`github.com/spf13/cobra`)
- **Email**: SMTP or SendGrid API
- **Database**: SQLite (for history tracking via `modernc.org/sqlite`)
- **Config**: YAML (`gopkg.in/yaml.v3`)

## Project Structure

```
eraser/
├── cmd/eraser/main.go       # CLI entry point, all commands defined here
├── internal/
│   ├── broker/broker.go     # Broker struct and YAML loading/filtering
│   ├── config/config.go     # User configuration (profile, email settings)
│   ├── email/
│   │   ├── sender.go        # Email sender interface
│   │   ├── smtp.go          # SMTP implementation
│   │   └── sendgrid.go      # SendGrid implementation
│   ├── history/history.go   # SQLite history tracking
│   └── template/
│       ├── template.go      # Template rendering engine
│       └── templates/       # Email templates (embedded)
│           ├── gdpr.tmpl
│           ├── ccpa.tmpl
│           └── generic.tmpl
├── data/brokers.yaml        # Generated from the CA CPPA registry (do not edit)
└── .github/workflows/       # GitHub Actions for monthly automation
```

## Key Concepts

### Broker
A data broker is a company that collects and sells personal information. Each broker has:
- `id`: Unique lowercase hyphenated identifier (e.g., `spokeo`, `been-verified`)
- `name`: Display name
- `email`: Privacy/removal contact email (required)
- `website`: Company website (optional)
- `opt_out_url`: Direct opt-out link (optional)
- `region`: `us`, `eu`, or `global`
- `category`: `people-search`, `marketing`, `background-check`, or `data-broker` (registry default)
- `tags`: `form-only` means the broker doesn't process email; `send` skips it
- `source`, `source_url`, `registry_id`: provenance of the entry

### Templates
Three email templates are available:
- **GDPR**: Invokes EU Article 17 "Right to Erasure"
- **CCPA**: Invokes California Consumer Privacy Act
- **Generic**: General privacy request referencing multiple laws

### Flow
CLI `send` and the web UI share one path in `internal/sendplan`:
`ForConfig` (regions, exclusions, form-only, resend window, daily cap from
history) picks brokers, and `Deliverer.Deliver` renders, sends, and records
each one. Don't add a send path that bypasses them.

1. Load user config from `~/.eraser/config.yaml`
2. Load brokers from `data/brokers.yaml`
3. Filter by region and exclusions
4. For each broker, render email template with user + broker data. `Render`
   requires a `config.Disclosure`: only name, email, the fields in
   `options.disclose`, and the broker's own `disclose` list reach the email
5. Send via SMTP or SendGrid
6. Record result in SQLite history

## Common Commands

```bash
# Build the project
go build -o eraser ./cmd/eraser

# Run tests
go test ./...

# List all brokers
./eraser list-brokers

# Preview emails without sending
./eraser send --dry-run

# Send removal requests
./eraser send

# View send history
./eraser status
```

## Inbox Monitoring Rules (internal/inbox)

- Fetch is two-pass: envelopes for the search window, then `BODY.PEEK[]` only
  for messages whose sender matches a broker (or whose In-Reply-To matches a
  sent Message-ID). Mailboxes are opened read-only (EXAMINE) for fetching.
- `Email.Authenticated` comes from the topmost `Authentication-Results`
  header only (DMARC pass or aligned DKIM pass). `ClassifyResponse` extracts
  no URLs from unauthenticated mail, and `inbox.Record` only updates pipeline
  status for authenticated mail. Keep both invariants.
- Store responses through `inbox.Record` (dedupes by broker and subject).
- UIDs are per-folder: `ArchiveEmails` only moves emails fetched from the
  configured folder.

## Configuration

User config is stored at `~/.eraser/config.yaml`. See `config.example.yaml` for the full schema. Key sections:
- `profile`: User's personal info (name, address, etc.)
- `email`: Provider settings (SMTP or SendGrid)
- `options`: Template choice, rate limiting, region filters

## Adding Brokers

`data/brokers.yaml` is GENERATED from the California CPPA data broker registry by
`cmd/registry-import` (logic in `internal/registry`). Never edit it by hand.
Put additions, overrides (e.g. `tags: [form-only]`), and exclusions in
`data/brokers.manual.yaml`. Each entry needs an https `source_url`. Then run
`go run ./cmd/registry-import -check-mx`.

`broker.LoadFromFile` validates every entry: single bare email, no personal
mailbox domains (Gmail, Outlook, …), unique ids, known region/category.

## Code Patterns

- **Error handling**: Wrap errors with context using `fmt.Errorf("context: %w", err)`
- **Config loading**: Uses YAML with struct tags for marshaling
- **Templates**: Go `text/template` with embedded files via `//go:embed`
- **CLI commands**: Defined in `cmd/eraser/main.go` using Cobra

## Important Files

| File | Purpose |
|------|---------|
| `cmd/eraser/main.go` | All CLI commands and main logic |
| `internal/broker/broker.go` | Broker type and database operations |
| `internal/template/template.go` | Email template rendering |
| `data/brokers.yaml` | Broker database, generated by `cmd/registry-import` |
| `config.example.yaml` | Example user configuration |

## Security Notes

- Never commit user configs (contains personal data)
- Config file should have 0600 permissions
- Use app passwords, not main email passwords
- Email credentials should use environment variables in CI

## Current Development Status (Web UI)

**All Phases Completed:**

1. **Phase 1: Foundation** - Web server with Chi router, Tailwind/HTMX, dashboard
2. **Phase 2: Setup Wizard** - Multi-step wizard for profile and email config
3. **Phase 3: Resend Integration** - Resend email sender implemented
4. **Phase 4: Broker Management UI** - Search/filter, status display, individual/bulk send
5. **Phase 5: History UI** - History list with partial template for HTMX updates
6. **Phase 6: Polish** - Cross-origin protection (`http.CrossOriginProtection`), Host allowlist, security headers

## Web UI Architecture

**Key Files:**
- `internal/web/server.go` - All routes and handlers, wizard state in server-side sessions, Host allowlist and cross-origin protection
- `internal/web/templates/` - HTML templates (layout.html, dashboard.html, brokers.html, history.html, setup/*.html)
- `internal/web/templates/partials/` - HTMX partial templates (broker-list.html, history-list.html)
- `internal/web/static/` - `css/app.css` (GENERATED by `scripts/build-css.sh` from templates; rebuild after changing classes, CI checks it) and `js/htmx.min.js` (htmx 1.9.10, verified against npm, loaded with SRI). No CDN or third-party assets: the CSP forbids them
- `internal/email/resend.go` - Resend API email sender

**Email Providers Supported:**
- `smtp` - Traditional SMTP (Gmail, Outlook)
- `sendgrid` - SendGrid API
- `resend` - Resend API (recommended for non-technical users)

**Running the Web UI:**
```bash
./eraser serve          # Starts on localhost:8080
./eraser serve -p 3000  # Custom port
```

**Key Features:**
- Setup wizard for first-time configuration
- Broker list with search, filter by category/region
- Individual and bulk send with real-time progress
- History tracking and status display
- Cross-origin POST/DELETE rejected via Sec-Fetch-Site/Origin (no tokens); requests with a foreign Host header rejected (DNS rebinding). Stored passwords are never rendered into pages

**Config Structure** (`internal/config/config.go`):
```go
type EmailConfig struct {
    Provider string         // "smtp", "sendgrid", or "resend"
    From     string
    SMTP     SMTPConfig
    SendGrid SendGridConfig
    Resend   ResendConfig
}

type ResendConfig struct {
    APIKey string `yaml:"api_key"`
}
```
