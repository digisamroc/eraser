package inbox

import (
	"regexp"
	"strings"

	"github.com/eraser-privacy/eraser/internal/config"
	"golang.org/x/net/publicsuffix"
)

var (
	authComment  = regexp.MustCompile(`\([^)]*\)`)
	authResult   = regexp.MustCompile(`^\s*(dmarc|dkim)\s*=\s*([a-z]+)`)
	authProperty = regexp.MustCompile(`header\.(from|d|i)\s*=\s*@?([a-z0-9.-]+)`)
)

// AuthServ identifies the Authentication-Results header written by the
// user's own mail provider. The zero value identifies nothing, so no mail
// is authenticated.
type AuthServ struct {
	ID   string // authserv-id the header must start with, lowercase
	NoID bool   // the provider writes no authserv-id (Microsoft)
}

// Known reports whether senders can be verified at all.
func (a AuthServ) Known() bool { return a.ID != "" || a.NoID }

// AuthServFor works out which header to trust from the inbox settings:
// inbox.authserv_id if set, otherwise Gmail's or Microsoft's own format. The
// server decides: a provider name only counts with no server set (config.Load
// then fills in the provider's own), so "gmail" on another server trusts nothing.
func AuthServFor(c config.InboxConfig) AuthServ {
	if c.AuthServID != "" {
		return AuthServ{ID: strings.ToLower(strings.TrimSpace(c.AuthServID))}
	}
	server := strings.ToLower(strings.TrimSpace(c.Server))
	switch {
	case server == "imap.gmail.com" || (server == "" && c.Provider == "gmail"):
		return AuthServ{ID: "mx.google.com"}
	case server == "outlook.office365.com" || server == "imap-mail.outlook.com" || (server == "" && c.Provider == "outlook"):
		return AuthServ{NoID: true}
	}
	return AuthServ{}
}

// Authenticated reports whether an Authentication-Results header value shows
// that a message really comes from fromDomain: a DMARC pass for that From
// domain, or a DKIM pass whose signing domain is aligned with it (same
// organizational domain, per the public suffix list). SPF alone is not enough,
// because it checks the envelope sender, not the From address users see.
//
// Pass only the topmost Authentication-Results header: it is added by the
// user's own mail provider. Headers further down can be written by anyone, and
// so can the topmost one if the provider adds none, so it must also carry the
// provider's authserv-id (as).
func Authenticated(header, fromDomain string, as AuthServ) bool {
	fromDomain = strings.ToLower(strings.TrimSpace(fromDomain))
	if fromDomain == "" || header == "" || !as.Known() {
		return false
	}
	// Comments can contain arbitrary text, including "dmarc=pass".
	header = authComment.ReplaceAllString(strings.ToLower(header), " ")

	parts := strings.Split(header, ";")
	// The header starts with the authserv-id (and an optional version) unless
	// the provider omits it, as Microsoft does; then it starts with a result.
	first := strings.TrimSpace(parts[0])
	if as.NoID {
		if !strings.Contains(first, "=") {
			return false
		}
	} else {
		if fields := strings.Fields(first); len(fields) == 0 || fields[0] != as.ID {
			return false
		}
		parts = parts[1:]
	}

	for _, part := range parts {
		m := authResult.FindStringSubmatch(part)
		if m == nil || m[2] != "pass" {
			continue
		}
		method := m[1]
		for _, p := range authProperty.FindAllStringSubmatch(part, -1) {
			prop, domain := p[1], p[2]
			switch {
			case method == "dmarc" && prop == "from" && domain == fromDomain:
				return true
			case method == "dkim" && (prop == "d" || prop == "i") && aligned(domain, fromDomain):
				return true
			}
		}
	}
	return false
}

// aligned implements relaxed DMARC alignment: both domains share an
// organizational domain (e.g. mail.spokeo.com and spokeo.com).
func aligned(a, b string) bool {
	orgA, errA := publicsuffix.EffectiveTLDPlusOne(a)
	orgB, errB := publicsuffix.EffectiveTLDPlusOne(b)
	return errA == nil && errB == nil && orgA == orgB
}
