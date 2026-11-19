# Security

Eraser handles the data it exists to protect: your name, contact details,
and optionally your address, phone, and date of birth, plus app passwords for
your mailbox. This document describes what it protects, against whom, and
what it doesn't cover.

## What's at stake

| Asset | Where it lives |
|-------|----------------|
| Profile (name, email, address, phone, DOB) | `~/.eraser/config.yaml` (0600) |
| SMTP and IMAP app passwords | `~/.eraser/config.yaml` (0600) |
| Send history, broker replies (bodies capped at 64 KB) | `~/.eraser/history.db` (0600) |
| Screenshots of filled forms | `~/.eraser/screenshots/` (0700 folder, 0600 files) |

`~/.eraser` itself is kept at 0700, including a folder left more open by an
older version. The config is saved to a new 0600 file and renamed into place,
so the previous file is never rewritten.

## Threats and mitigations

**Sending your data to the wrong people.**
Broker contacts come from the California CPPA registry, where brokers register
their own addresses (`cmd/registry-import`). Personal-mailbox domains (Gmail,
Outlook, …) are rejected, and manual additions must cite a source. Emails
contain only your name and email unless you opt in to more, globally or per
broker (`options.disclose`, per-broker `disclose`). Mail goes out over TLS
(implicit or STARTTLS, never falling back); plaintext SMTP is refused except
to a relay on this machine.

**Spoofed "broker" email.**
A reply only counts as a broker's if your mail provider verified it: the
topmost `Authentication-Results` header must be your provider's (its
authserv-id, e.g. `mx.google.com`) and show DMARC pass, or a DKIM pass aligned
with the From domain. Lower headers, which a sender can forge, are ignored.
Links in unverified mail are never extracted, and unverified mail can't change
a broker's status. A stored reply's body, links and verification always come
from the same email, and an unverified email never replaces a verified one.
Replies are also matched to your requests by `In-Reply-To` against
Message-IDs that only the broker saw.

**Fake bounces.**
`cleanup-bounces --remove` only removes a broker for a verified bounce that
refers to a request Eraser sent, by its Message-ID, and names that broker's
address if it lists recipients. Anyone can send authenticated mail from their
own domain naming a broker, but not the Message-ID of your request.

**Malicious or redirected web pages (`fill`, `confirm`).**
A page must be https and belong to the broker (`broker.OwnsURL`). `fill`
checks it before navigating, after the page loads (catching redirects), after
a CAPTCHA wait, and before submitting, and each field is filled only while the
page is still on the checked origin (one in-page step per field, so a page
can't navigate between the check and the fill). `confirm` checks every
redirect hop. Only a submit button inside a form Eraser filled is clicked.
Chrome always runs with its sandbox.

**Malicious websites attacking the local web UI.**
The UI listens only on `127.0.0.1`. Requests whose Host header isn't
`localhost:PORT` or `127.0.0.1:PORT` are refused, which blocks DNS rebinding.
Cross-origin state-changing requests are rejected
(`http.CrossOriginProtection`). Stored passwords are never written into pages.

**Compromised third-party code.**
The web UI loads no external scripts, styles, or fonts, and the CSP forbids
them. htmx is vendored and verified against the npm release, and CSS is built
with a pinned, checksum-verified Tailwind CLI. CI runs `govulncheck` (failing on
any reachable vulnerability) and `gitleaks`.

**Reading your mailbox more than needed.**
Mailboxes are opened read-only. Only envelopes are fetched for recent mail, and
full bodies are downloaded only for broker messages. Nothing is marked read.

## Known limitations

- **Other local users and processes** can reach the web UI on
  `127.0.0.1:PORT` while it runs; there's no login. Don't run `eraser serve` on
  a shared machine.
- **Inline scripts:** the web UI's CSP still allows `'unsafe-inline'` scripts
  (templates use inline handlers). Output escaping by `html/template` is the
  main XSS defense.
- **Plain-text secrets on disk:** app passwords are stored in
  `config.yaml`, protected only by file permissions. Use app passwords, never
  your main password, and revoke them if the file is exposed.
- **Sender verification depends on your provider.** It needs the provider to
  add an `Authentication-Results` header and Eraser to know its authserv-id.
  Gmail and Outlook are built in; for others set `inbox.authserv_id`, or every
  email is treated as unverified.
- **Archiving without IMAP MOVE:** the fallback (COPY + EXPUNGE) also removes
  other messages already flagged `\Deleted` in that folder. Gmail and Outlook
  support MOVE.
- **Registry accuracy:** addresses are what brokers registered; some may be
  stale. Websites and opt-out URLs whose host doesn't exist are dropped when
  the list is regenerated with `-check-mx`, but a typo that someone has
  already registered would still pass. The 15 `form-only` overrides come from one user's report (upstream PR
  #29) and are cited as such.
- **Malware running as your user** can read everything above; that's out of
  scope.

## Reporting a vulnerability

Please report security problems privately using GitHub's "Report a
vulnerability" (private security advisory) on this repository, not in a
public issue. Include steps to reproduce and the version or commit.
