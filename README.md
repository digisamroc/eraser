# Eraser

Take back your privacy. Eraser sends data removal requests to 750+ data brokers on your behalf—for free.

You know those sites like Spokeo, BeenVerified, and Whitepages that have your home address, phone number, and family members' names? They're called data brokers, and there are hundreds of them. Services like Incogni and DeleteMe charge $100+/year to send opt-out requests to these companies. Eraser does the same thing, but it's open source and completely free.

### What to Expect

**The good:** Eraser automatically sends removal request emails to 750+ data brokers. Many brokers process these requests automatically—you send the email, they remove your data, done.

**The reality:** Some brokers require additional steps. They might send you a confirmation link to click, ask you to fill out a form on their website, or request identity verification. Eraser tracks these responses and shows you exactly what needs manual attention.

**The bottom line:** You're not paying $100+/year, and you're taking real action to protect your privacy. Even with some manual steps, Eraser handles the heavy lifting and gives you a fighting chance against the data broker industry.

---

## The Easy Way (Web Interface)

If you're not comfortable with command-line tools, Eraser has a visual interface that runs in your web browser.

### What You'll Need

1. **Go** installed on your computer ([download here](https://go.dev/dl/))
2. A **Gmail account** to send emails from (with an App Password—setup instructions below)

### Getting Started

**Step 1: Download Eraser**

Open your terminal (on Mac, search for "Terminal"; on Windows, use PowerShell) and run:

```bash
git clone https://github.com/eraser-privacy/eraser.git
cd eraser
go build -o eraser ./cmd/eraser
```

**Step 2: Start the Web Interface**

```bash
./eraser serve
```

Open your browser and go to `http://localhost:8080`

**Step 3: Complete the Setup Wizard**

The wizard walks you through entering your personal information (the data brokers need this to find your records) and setting up email. Just follow the prompts.

**Step 4: Send Removal Requests**

From the dashboard, you can:
- Browse the list of 750+ data brokers
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

**Daily sending limits:** Gmail allows ~500 emails per day. Eraser automatically chunks large sends across multiple days (250/day to stay safe) so you don't hit rate limits.

---

## For Developers: CLI Usage

If you prefer the command line, Eraser has a full CLI.

### Installation

```bash
git clone https://github.com/eraser-privacy/eraser.git
cd eraser
go build -o eraser ./cmd/eraser
```

### Quick Start

```bash
# Interactive setup
./eraser init

# Preview what would be sent (no emails go out)
./eraser send --dry-run

# Send removal requests to all brokers
./eraser send

# Check your history
./eraser status
```

### Commands

| Command | What it does |
|---------|--------------|
| `eraser init` | Interactive config setup |
| `eraser send` | Send removal requests |
| `eraser send --dry-run` | Preview without sending |
| `eraser list-brokers` | Show all 750+ brokers |
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
  # Optional but helps brokers find your records
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
    port: 465
    username: jane@gmail.com
    password: your-16-char-app-password  # From Google App Passwords
    use_tls: true

options:
  template: generic  # or "gdpr" or "ccpa"
  rate_limit_ms: 2000  # delay between emails

  # Optional: only target specific regions
  # regions:
  #   - us
  #   - global

  # Optional: skip specific brokers
  # excluded_brokers:
  #   - spokeo
  #   - whitepages
```

### Email Templates

Eraser includes three templates:

- **GDPR** — Invokes Article 17 "Right to Erasure" under EU law
- **CCPA** — Invokes California Consumer Privacy Act rights
- **Generic** — References multiple privacy laws, works anywhere

The generic template is a good default if you're not sure.

### Adding Brokers

The broker database is at `data/brokers.yaml`. To add one:

```yaml
- id: example-broker
  name: Example Broker
  email: privacy@example.com
  website: https://example.com
  opt_out_url: https://example.com/optout
  region: us  # us, eu, or global
  category: people-search  # people-search, marketing, or background-check
```

Or use the interactive command:

```bash
./eraser add-broker
```

---

## Automate It with GitHub Actions

Want Eraser to run automatically every month? Fork the repo and set up GitHub Actions.

### Setup

1. Fork this repository
2. Go to Settings → Secrets and Variables → Actions
3. Add these secrets:

**Required:**
| Secret | Value |
|--------|-------|
| `ERASER_FIRST_NAME` | Your first name |
| `ERASER_LAST_NAME` | Your last name |
| `ERASER_EMAIL` | Your Gmail address |
| `ERASER_EMAIL_PROVIDER` | `smtp` |
| `ERASER_TEMPLATE` | `gdpr`, `ccpa`, or `generic` |
| `ERASER_SMTP_HOST` | `smtp.gmail.com` |
| `ERASER_SMTP_PORT` | `465` |
| `ERASER_SMTP_USERNAME` | Your Gmail address |
| `ERASER_SMTP_PASSWORD` | Your Gmail App Password |

**Optional (but recommended):**
| Secret | Value |
|--------|-------|
| `ERASER_ADDRESS` | Street address |
| `ERASER_CITY` | City |
| `ERASER_STATE` | State |
| `ERASER_ZIP_CODE` | ZIP code |
| `ERASER_COUNTRY` | Country |
| `ERASER_PHONE` | Phone number |

The workflow runs on the 1st of every month. You can also trigger it manually from the Actions tab.

---

## Security Notes

- **Your config file contains personal data.** Don't commit it to git. The file is created with restricted permissions (readable only by you).
- **Use app passwords, not your real password.** For Gmail, this is required. For other providers, it's still a good idea.
- **Consider using a dedicated email.** This keeps your removal request activity separate from your main inbox.

---

## Does This Actually Work?

Yes, with caveats:

- **Most brokers comply.** They're legally required to under GDPR (EU) and CCPA (California). Even brokers not covered by these laws often honor requests to avoid liability.
- **Some require manual steps.** About 20-30% of brokers will respond asking you to:
  - Click a confirmation link (Eraser detects these and shows them to you)
  - Fill out an opt-out form on their website (Eraser tracks these as "pending tasks")
  - Verify your identity via email reply
- **It's not instant.** Brokers have up to 30-45 days to process requests (varies by law). Some are faster.
- **You'll need to repeat this.** Data brokers buy and sell data continuously. Running Eraser monthly keeps you off their lists.

**The Pipeline view** in Eraser's web UI shows you exactly which brokers need manual attention. It's not fully automated, but it's free—and it does the tedious work of sending 750+ emails and tracking responses for you.

---

## How It Compares

| Service | Price | Brokers | Open Source |
|---------|-------|---------|-------------|
| **Eraser** | Free | 750+ | Yes |
| Incogni | $77/year | 180+ | No |
| DeleteMe | $129/year | 750+ | No |
| Privacy Duck | $500+/year | 500+ | No |

---

## Contributing

Contributions are welcome. The most helpful things:

- **Adding brokers** — The database at `data/brokers.yaml` can always use more entries
- **Template improvements** — Better wording for removal requests
- **Bug fixes** — Found something broken? PRs welcome
- **Documentation** — Typos, clarifications, better examples

---

## Project Structure

```
eraser/
├── cmd/eraser/main.go       # CLI entry point
├── internal/
│   ├── broker/              # Broker loading and filtering
│   ├── config/              # Configuration handling
│   ├── email/               # SMTP, SendGrid, Resend senders
│   ├── history/             # SQLite request tracking
│   ├── template/            # Email template rendering
│   └── web/                 # Web UI server and handlers
├── data/brokers.yaml        # 750+ broker database
└── config.example.yaml      # Example configuration
```

---

## License

MIT — do whatever you want with it.

---

## Disclaimer

This tool sends legitimate data removal requests based on privacy laws. It's not legal advice. Not all brokers are required to comply with all requests, and response times vary. But it works, and it's free.
