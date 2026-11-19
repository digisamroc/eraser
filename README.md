# Eraser

Take back your privacy. Eraser sends data removal requests to nearly 600 registered data brokers on your behalf—for free.

You know those sites like Spokeo, BeenVerified, and Whitepages that have your home address, phone number, and family members' names? They're called data brokers, and there are hundreds of them. Paid services send opt-out requests to these companies for you. Eraser automates the email part of that work. It's open source, free, and runs on your own computer.

### What to Expect

**The good:** Eraser sends removal request emails to nearly 600 data brokers registered with the State of California, using contact addresses the brokers gave the state themselves. By default each email contains only your name and email address.

**The reality:** Some brokers require additional steps. They might send you a confirmation link to click, ask you to fill out a form on their website, or request identity verification. Eraser tracks these responses and shows you exactly what needs manual attention.

**The bottom line:** It's free and it handles the repetitive part, but expect some manual follow-up, and re-run it periodically (see "Running It Monthly").

---

## The Easy Way (Web Interface)

If you're not comfortable with command-line tools, Eraser has a visual interface that runs in your web browser.

### What You'll Need

1. **Go** installed on your computer ([download here](https://go.dev/dl/))
2. An **email account with SMTP access** to send from. Gmail works (with an App Password, setup below), and so does any other provider that offers SMTP, such as Fastmail, Proton (via Bridge) or Namecheap Private Email

### Getting Started

**Step 1: Download Eraser**

Open your terminal (on Mac, search for "Terminal"; on Windows, use PowerShell) and run:

```bash
git clone https://github.com/kesmit13/eraser.git
cd eraser
go build -o eraser ./cmd/eraser
```

**Step 2: Start the Web Interface**

```bash
./eraser serve
```

Open your browser and go to `http://localhost:8080`

**Step 3: Complete the Setup Wizard**

The wizard walks you through entering your personal information (the data brokers need this to find your records) and setting up email. It starts with Gmail's server (`smtp.gmail.com`, port 465); for another provider, enter its SMTP server and port from its mail settings. Port 465 uses TLS and 587 uses STARTTLS.

**Step 4: Send Removal Requests**

From the dashboard, you can:
- Browse the list of registered data brokers
- Send requests one at a time or in bulk
- Track which requests have been sent and their status

That's it. The whole process takes about 10 minutes to set up, and then Eraser handles the rest.

### Setting Up Gmail

Eraser uses your Gmail account to send removal requests. You'll need to create an "App Password" (Google doesn't allow third-party apps to use your regular password).

**One-time setup (takes 2 minutes):**

1. Go to your [Google Account](https://myaccount.google.com)
2. Enable **2-Factor Authentication** if you haven't already (Security → 2-Step Verification)
3. Go to [App Passwords](https://myaccount.google.com/apppasswords)
4. Select "Mail" and your device, then click "Generate"
5. Copy the 16-character password (looks like `xxxx xxxx xxxx xxxx`)

That's the password you'll use in Eraser's setup wizard. Your regular Gmail password won't work.

**Daily sending limits:** Gmail allows ~500 emails per day. Eraser sends at most 250 per rolling 24 hours (`options.daily_limit`), counting earlier runs and both the CLI and web UI. Run it again later to continue. Both `eraser send` and the web UI's "Send all" skip brokers you've sent to in the last 30 days (`options.resend_after_days`), so re-running doesn't double-send. An interrupted bulk send is never resumed automatically; click "Send all" (or run `eraser send`) again to continue where it left off.

---

## For Developers: CLI Usage

If you prefer the command line, Eraser has a full CLI.

### Installation

```bash
git clone https://github.com/kesmit13/eraser.git
cd eraser
go build -o eraser ./cmd/eraser
```

### Quick Start

```bash
# Interactive setup
./eraser init

# Preview what would be sent (no emails go out)
./eraser send --dry-run

# Send removal requests (shows a summary and asks you to type "yes")
./eraser send

# Check your history
./eraser status
```

### Commands

| Command | What it does |
|---------|--------------|
| `eraser init` | Interactive config setup |
| `eraser send` | Send removal requests (asks for confirmation) |
| `eraser send --dry-run` | Preview without sending |
| `eraser send --limit 20` | Send to at most 20 brokers this run |
| `eraser send --yes` | Skip the confirmation (e.g. in scripts) |
| `eraser send --force-resend` | Include brokers contacted within `resend_after_days` |
| `eraser list-brokers` | Show all brokers |
| `eraser status` | View history and stats |
| `eraser status --limit 50` | Show more history |
| `eraser add-broker` | Add a custom broker |
| `eraser serve` | Start web interface |
| `eraser serve -p 3000` | Web interface on custom port |

### Configuration File

Your config lives at `~/.eraser/config.yaml`. Here's the full schema:

```yaml
profile:
  first_name: Jane
  last_name: Doe
  email: jane@example.com
  # Optional. Kept locally; NOT sent unless listed in options.disclose
  address: "123 Main Street"
  city: "San Francisco"
  state: "CA"
  zip_code: "94102"
  country: "USA"
  phone: "+1-555-123-4567"
  date_of_birth: "1990-01-15"

email:
  provider: smtp
  from: jane@gmail.com

  smtp:
    host: smtp.gmail.com
    port: 465            # 465 = implicit TLS, 587 = STARTTLS
    username: jane@gmail.com
    password: your-16-char-app-password  # From Google App Passwords
    use_tls: true

options:
  template: generic  # or "gdpr" or "ccpa"
  rate_limit_ms: 2000  # delay between emails

  # Optional: extra profile fields to send (name and email are always sent)
  # disclose: [location, street_address, phone, date_of_birth]

  # Optional: only target specific regions
  # regions:
  #   - us
  #   - global

  # Optional: skip specific brokers
  # excluded_brokers:
  #   - spokeo
  #   - whitepages
```

### What Gets Sent

By default, removal emails contain only your **name and email**. Your address, phone, and date of birth stay on your machine. California's rules let a business verify a deletion request by matching about two data points it already holds, and name plus email are two. Sending every broker your date of birth would give it to companies that may never have had it.

- To send more to every broker, list fields in `options.disclose`.
- If one broker can't find you and asks for more, add a `disclose` override for just that broker in `data/brokers.manual.yaml`, citing its reply or privacy page:

  ```yaml
  overrides:
    - email: privacy@somebroker.com
      disclose: [date_of_birth]
      source_url: https://somebroker.com/privacy
  ```

`eraser send --dry-run` prints exactly which fields are sent and which are withheld.

### Email Templates

Eraser includes three templates:

- **GDPR** — Invokes Article 17 "Right to Erasure" under EU law
- **CCPA** — Invokes California Consumer Privacy Act rights
- **Generic** — References multiple privacy laws, works anywhere

The generic template is a good default if you're not sure.

### Where the Broker List Comes From

`data/brokers.yaml` is generated from the [California data broker registry](https://cppa.ca.gov/data_broker_registry/). California law requires data brokers to register with the state and give their own contact email, so every address in the list is one the company submitted itself. When generating the list, Eraser:

- merges registrations that share an email address,
- rejects personal mailboxes (Gmail, Outlook, etc.),
- with `-check-mx`, drops domains that can't receive mail, and website or opt-out URLs whose host doesn't exist (often a typo that anyone could register).

Some brokers don't process emailed requests. They're tagged `form-only`; `send` skips them, and the web UI links to their form instead.

A workflow (`.github/workflows/registry-sync.yml`) regenerates the list monthly and opens a PR when it changes. To regenerate it yourself:

```bash
go run ./cmd/registry-import -check-mx
```

### Adding or Correcting Brokers

Don't edit `data/brokers.yaml` directly; it's overwritten on regeneration. Edit `data/brokers.manual.yaml` instead, then regenerate:

```yaml
add:        # brokers not in the registry
  - id: example-broker
    name: Example Broker
    email: privacy@example.com
    region: us                 # us, eu, or global
    category: people-search    # people-search, marketing, background-check, data-broker
    source_url: https://example.com/privacy   # required: where you got this
overrides:  # change a registry entry, matched by email
  - email: privacy@somebroker.com
    tags: [form-only]
    opt_out_url: https://somebroker.com/dsr
    source_url: https://somebroker.com/privacy
exclude:    # drop a registry entry, matched by email
  - email: old@somebroker.com
    reason: Bounces
    source_url: https://example.com/where-this-was-reported
```

Every entry needs an `https` `source_url` so it can be checked later.

---

## Running It Monthly

Brokers keep collecting data, so re-running helps. `eraser send` is safe to repeat: it skips brokers you sent to in the last 30 days and never goes over the daily limit. A monthly cron job on your own computer works:

```cron
# 9am on the 1st of each month
0 9 1 * * cd /path/to/eraser && ./eraser send --yes >> ~/.eraser/send.log 2>&1
```

Running it on GitHub Actions instead would mean storing your personal details and email password as repository secrets. Forks of public repositories are public too, and so are their Actions logs. Keep it on your own machine.

---

## Inbox Monitoring (optional)

`eraser monitor`, and "Scan inbox" in the web UI, read broker replies over IMAP and sort them as done, form required, confirmation needed, more info required, rejected, or pending. They need an inbox app password in `config.yaml` (Settings in the web UI). Safeguards:

- **Read-only.** Mailboxes are opened read-only. Nothing is marked as read, and nothing is moved unless you turn on `auto_archive`.
- **Broker mail only.** For recent mail, only the sender and subject are fetched. Full message bodies are downloaded only for messages from a registered broker domain, or replies to one of your sent requests (matched by Message-ID). Personal mailbox domains like Gmail never count as brokers.
- **Verified senders only.** Links are only taken from mail your provider verified as genuinely from that sender (DMARC, or aligned DKIM, in the `Authentication-Results` header your provider adds). Anything else is saved for your review with its links dropped, and doesn't change a broker's status. A spoofed "broker" email can't feed a link to `fill` or `confirm`.
- **Your provider's header only.** Eraser knows Gmail's and Outlook's headers. For any other provider, set `inbox.authserv_id` (see `config.example.yaml`); until then no sender counts as verified.
- **Real bounces only.** `cleanup-bounces --remove` only removes a broker for a verified bounce that refers to a request Eraser sent (by Message-ID). A forged "undeliverable" email can't remove a broker.
- **Stored text is capped.** Broker reply text is stored locally (capped at 64 KB) only so replies can be reclassified later.

If a broker replies that it needs more information to find you, the reply is flagged as "info required". You can then add a per-broker `disclose` override (see "What Gets Sent").

## Form Filling and Confirmation Links (optional)

`eraser fill` opens broker opt-out forms in headless Chrome and fills them in. `eraser confirm` clicks confirmation links. Safeguards:

- **The broker's own site only.** A page must be https and on the broker's registered domain, or under its registered opt-out URL. This is checked before loading, after any redirect (including script redirects), and again before submitting. Each field is only filled while the page is still on that site, so a page that navigates away mid-fill gets nothing more. `confirm` checks every redirect hop.
- **Verified emails only.** Links taken from your inbox are only used if the email's sender was verified (see Inbox Monitoring).
- **Only what you disclose.** Forms get your name and email plus the fields in `options.disclose` and that broker's own `disclose` list. Nothing else is typed in.
- **One form only.** Fields go into the form that matches your profile best, not a newsletter or search box elsewhere on the page, and only that form is submitted. If two forms match equally well, nothing is filled and you fill it by hand.
- **No fake success.** The tool only reports "submitted" after clicking the form's own submit button. Without one, it tells you to submit by hand. `confirm` marks a broker confirmed only when the page's visible text clearly says it worked; if the page says nothing either way, or both, the broker's status is left alone and you're asked to open the link yourself.
- **Private screenshots.** Screenshots of filled forms are saved owner-only in `~/.eraser/screenshots`.

On Ubuntu 23.10+, Chrome may fail to start with "No usable sandbox". Allow unprivileged user namespaces (`kernel.apparmor_restrict_unprivileged_userns=0` via `sysctl`), or install Chrome's AppArmor profile. Don't use `--no-sandbox`: the sandbox protects you from the sites `fill` opens.

## Privacy: What Leaves Your Computer

Eraser runs locally and has no telemetry. Nothing is sent anywhere except:

| What | Goes to | When |
|------|---------|------|
| Removal emails: your name, email, and only the fields you choose to disclose | Each broker's registered address, through your own mail provider | `send`, or "Send" in the web UI |
| Your mail password | Your mail provider (SMTP/IMAP over TLS) | Sending, and inbox monitoring if enabled |
| Form fields you disclose to that broker | The broker's own https site | `fill` (optional) |
| A confirmation link request | The broker's own https site | `confirm` (optional) |

Everything else stays in `~/.eraser/` on your computer: `config.yaml` (owner-only, 0600), `history.db` (send history and broker replies), and `screenshots/` (owner-only). The web UI listens only on `127.0.0.1`, refuses requests addressed to other host names, and loads no third-party scripts, fonts, or styles. See [SECURITY.md](SECURITY.md) for the threat model.

## Security Notes

- **Your config file contains personal data.** Don't commit it to git. It's created with owner-only permissions.
- **Use app passwords, not your real password.** For Gmail, this is required. For other providers, it's still a good idea.
- **Consider using a dedicated email.** This keeps your removal request activity separate from your main inbox.

---

## Does This Actually Work?

Yes, with caveats:

- **Legal obligations vary.** Brokers registered in California must honor CCPA deletion requests from California residents, and GDPR covers people in the EU. Elsewhere, compliance is voluntary.
- **Some require manual steps.** Some brokers will reply asking you to:
  - Click a confirmation link (Eraser detects these and shows them to you)
  - Fill out an opt-out form on their website (Eraser tracks these as "pending tasks")
  - Send more details to find your records (flagged as "info required")
- **It's not instant.** Brokers have up to 30-45 days to process requests (varies by law). Some are faster.
- **You'll need to repeat this.** Data brokers buy and sell data continuously. Running Eraser monthly keeps you off their lists.

**The Pipeline view** in Eraser's web UI shows you exactly which brokers need manual attention. It's not fully automated, but it's free—and it does the tedious work of sending hundreds of emails and tracking responses for you.

---

## How It Compares

Paid services such as DeleteMe and Incogni also submit web forms, re-check broker sites, and handle follow-ups for you. Eraser automates the emailed requests and tracks the replies, and leaves form submissions to you (with optional help from `fill`). Choose based on how much manual follow-up you're willing to do.

---

## Contributing

Contributions are welcome. The most helpful things:

- **Adding brokers** — Add cited entries to `data/brokers.manual.yaml` (see above); `data/brokers.yaml` is generated
- **Template improvements** — Better wording for removal requests
- **Bug fixes** — Found something broken? PRs welcome
- **Documentation** — Typos, clarifications, better examples

Development notes:
- Install the hooks with `pre-commit install`. Every commit runs gofmt, vet, tests, golangci-lint and gitleaks.
- The web UI loads nothing from third parties. If you change Tailwind classes in `internal/web/templates/` or in HTML written by `internal/web/*.go`, rebuild the stylesheet with `scripts/build-css.sh` and commit `internal/web/static/css/app.css`. The script downloads a pinned, checksum-verified Tailwind CLI, and CI fails if the stylesheet is stale.

---

## Project Structure

```
eraser/
├── cmd/
│   ├── eraser/              # CLI entry point (all commands)
│   └── registry-import/     # Regenerates data/brokers.yaml from the CA registry
├── internal/
│   ├── broker/              # Broker type, validation, filtering, OwnsURL
│   ├── browser/             # Headless Chrome form filling and confirmation links
│   ├── config/              # Configuration and disclosure settings
│   ├── email/               # SMTP sender (implicit TLS / STARTTLS)
│   ├── history/             # SQLite send history and broker replies
│   ├── inbox/               # IMAP monitoring, sender verification, classification
│   ├── registry/            # CPPA registry parsing and the manual overlay
│   ├── sendplan/            # Shared send rules (filters, resend window, daily cap)
│   ├── template/            # Email template rendering
│   └── web/                 # Local web UI
├── data/
│   ├── brokers.yaml         # Generated: do not edit
│   └── brokers.manual.yaml  # Hand-maintained additions, overrides, exclusions
├── docs/fork-plan.md        # Hardening plan and results
├── SECURITY.md              # Threat model and reporting
└── config.example.yaml      # Example configuration
```

---

## License

MIT — do whatever you want with it.

---

## Disclaimer

This tool sends legitimate data removal requests based on privacy laws. It's not legal advice. Not all brokers are required to comply with all requests, and response times vary.
