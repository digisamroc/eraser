package inbox

import (
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"
)

var (
	authComment  = regexp.MustCompile(`\([^)]*\)`)
	authResult   = regexp.MustCompile(`^\s*(dmarc|dkim)\s*=\s*([a-z]+)`)
	authProperty = regexp.MustCompile(`header\.(from|d|i)\s*=\s*@?([a-z0-9.-]+)`)
)

// Authenticated reports whether an Authentication-Results header value shows
// that a message really comes from fromDomain: a DMARC pass for that From
// domain, or a DKIM pass whose signing domain is aligned with it (same
// organizational domain, per the public suffix list). SPF alone is not enough,
// because it checks the envelope sender, not the From address users see.
//
// Pass only the topmost Authentication-Results header: it is added by the
// user's own mail provider. Headers further down can be written by anyone.
func Authenticated(header, fromDomain string) bool {
	fromDomain = strings.ToLower(strings.TrimSpace(fromDomain))
	if fromDomain == "" || header == "" {
		return false
	}
	// Comments can contain arbitrary text, including "dmarc=pass".
	header = authComment.ReplaceAllString(strings.ToLower(header), " ")

	for _, part := range strings.Split(header, ";") {
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
