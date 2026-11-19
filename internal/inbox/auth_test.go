package inbox

import (
	"testing"

	"github.com/eraser-privacy/eraser/internal/config"
)

func TestAuthenticated(t *testing.T) {
	tests := []struct {
		name   string
		header string
		from   string
		want   bool
		as     AuthServ // defaults to Gmail's mx.google.com
	}{
		{"gmail dmarc pass",
			`mx.google.com; dkim=pass header.i=@spokeo.com header.s=s1 header.b=abc; spf=pass (google.com: domain of bounce@spokeo.com designates 1.2.3.4 as permitted sender) smtp.mailfrom=bounce@spokeo.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=spokeo.com`,
			"spokeo.com", true, AuthServ{}},
		{"outlook format, no authserv-id",
			`spf=pass (sender IP is 1.2.3.4) smtp.mailfrom=spokeo.com; dkim=pass (signature was verified) header.d=spokeo.com;dmarc=pass action=none header.from=spokeo.com;compauth=pass reason=100`,
			"spokeo.com", true, AuthServ{NoID: true}},
		{"aligned dkim from subdomain",
			`mx.google.com; dkim=pass header.i=@mail.spokeo.com; spf=neutral smtp.mailfrom=x@y.example`,
			"spokeo.com", true, AuthServ{}},
		{"aligned dkim, from subdomain",
			`mx.google.com; dkim=pass header.d=spokeo.com`,
			"privacy.spokeo.com", true, AuthServ{}},
		{"dkim pass for an unrelated domain",
			`mx.google.com; dkim=pass header.i=@mailer.evil.example; spf=pass smtp.mailfrom=evil.example; dmarc=fail header.from=spokeo.com`,
			"spokeo.com", false, AuthServ{}},
		{"spf only is not enough",
			`mx.google.com; spf=pass smtp.mailfrom=spokeo.com`,
			"spokeo.com", false, AuthServ{}},
		{"dmarc pass for a different from domain",
			`mx.google.com; dmarc=pass header.from=evil.example`,
			"spokeo.com", false, AuthServ{}},
		{"dmarc fail",
			`mx.google.com; dkim=fail header.d=spokeo.com; dmarc=fail header.from=spokeo.com`,
			"spokeo.com", false, AuthServ{}},
		{"lookalike domain",
			`mx.google.com; dkim=pass header.d=spokeo.com.evil.example; dmarc=pass header.from=spokeo.com.evil.example`,
			"spokeo.com", false, AuthServ{}},
		{"one failing and one aligned passing signature",
			`mx.google.com; dkim=fail header.d=spokeo.com; dkim=pass header.d=spokeo.com`,
			"spokeo.com", true, AuthServ{}},
		{"uppercase",
			`MX.GOOGLE.COM; DMARC=PASS header.from=Spokeo.COM`,
			"spokeo.com", true, AuthServ{}},
		{"no header", ``, "spokeo.com", false, AuthServ{}},
		{"no from domain", `mx.google.com; dmarc=pass header.from=spokeo.com`, "", false, AuthServ{}},
		{"comment containing dmarc=pass",
			`mx.google.com; spf=softfail (note: dmarc=pass header.from=spokeo.com) smtp.mailfrom=evil.example`,
			"spokeo.com", false, AuthServ{}},
		{"header from another server",
			`attacker.example; dmarc=pass header.from=spokeo.com`,
			"spokeo.com", false, AuthServ{}},
		{"authserv-id with a version",
			`mx.google.com 1; dmarc=pass header.from=spokeo.com`,
			"spokeo.com", true, AuthServ{}},
		{"no authserv-id where one is expected",
			`dmarc=pass header.from=spokeo.com`,
			"spokeo.com", false, AuthServ{}},
		{"authserv-id where Microsoft writes none",
			`attacker.example; dmarc=pass header.from=spokeo.com`,
			"spokeo.com", false, AuthServ{NoID: true}},
		{"configured authserv-id",
			`mail.example.net; dmarc=pass header.from=spokeo.com`,
			"spokeo.com", true, AuthServ{ID: "mail.example.net"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			as := tt.as
			if !as.Known() {
				as = AuthServ{ID: "mx.google.com"}
			}
			if got := Authenticated(tt.header, tt.from, as); got != tt.want {
				t.Errorf("Authenticated() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Without knowing which header the provider writes, any header could be the
// sender's own, so nothing is authenticated.
func TestAuthenticatedFailsClosedForUnknownProvider(t *testing.T) {
	if Authenticated(`mx.example; dmarc=pass header.from=spokeo.com`, "spokeo.com", AuthServ{}) {
		t.Error("authenticated with no known authserv-id")
	}
}

func TestAuthServFor(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.InboxConfig
		want AuthServ
	}{
		{"gmail provider", config.InboxConfig{Provider: "gmail"}, AuthServ{ID: "mx.google.com"}},
		{"gmail server", config.InboxConfig{Provider: "imap", Server: "imap.gmail.com"}, AuthServ{ID: "mx.google.com"}},
		{"outlook provider", config.InboxConfig{Provider: "outlook"}, AuthServ{NoID: true}},
		{"outlook server", config.InboxConfig{Server: "outlook.office365.com"}, AuthServ{NoID: true}},
		{"configured", config.InboxConfig{Provider: "gmail", AuthServID: "MX.Example.NET"}, AuthServ{ID: "mx.example.net"}},
		{"other provider", config.InboxConfig{Provider: "imap", Server: "imap.example.net"}, AuthServ{}},
		// A provider name doesn't vouch for someone else's server.
		{"gmail provider, other server", config.InboxConfig{Provider: "gmail", Server: "imap.example.net"}, AuthServ{}},
		{"outlook provider, other server", config.InboxConfig{Provider: "outlook", Server: "imap.example.net"}, AuthServ{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AuthServFor(tt.cfg); got != tt.want {
				t.Errorf("AuthServFor() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
