package inbox

import "testing"

func TestAuthenticated(t *testing.T) {
	tests := []struct {
		name   string
		header string
		from   string
		want   bool
	}{
		{"gmail dmarc pass",
			`mx.google.com; dkim=pass header.i=@spokeo.com header.s=s1 header.b=abc; spf=pass (google.com: domain of bounce@spokeo.com designates 1.2.3.4 as permitted sender) smtp.mailfrom=bounce@spokeo.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=spokeo.com`,
			"spokeo.com", true},
		{"outlook format, no authserv-id",
			`spf=pass (sender IP is 1.2.3.4) smtp.mailfrom=spokeo.com; dkim=pass (signature was verified) header.d=spokeo.com;dmarc=pass action=none header.from=spokeo.com;compauth=pass reason=100`,
			"spokeo.com", true},
		{"aligned dkim from subdomain",
			`mx.google.com; dkim=pass header.i=@mail.spokeo.com; spf=neutral smtp.mailfrom=x@y.example`,
			"spokeo.com", true},
		{"aligned dkim, from subdomain",
			`mx.google.com; dkim=pass header.d=spokeo.com`,
			"privacy.spokeo.com", true},
		{"dkim pass for an unrelated domain",
			`mx.google.com; dkim=pass header.i=@mailer.evil.example; spf=pass smtp.mailfrom=evil.example; dmarc=fail header.from=spokeo.com`,
			"spokeo.com", false},
		{"spf only is not enough",
			`mx.google.com; spf=pass smtp.mailfrom=spokeo.com`,
			"spokeo.com", false},
		{"dmarc pass for a different from domain",
			`mx.google.com; dmarc=pass header.from=evil.example`,
			"spokeo.com", false},
		{"dmarc fail",
			`mx.google.com; dkim=fail header.d=spokeo.com; dmarc=fail header.from=spokeo.com`,
			"spokeo.com", false},
		{"lookalike domain",
			`mx.google.com; dkim=pass header.d=spokeo.com.evil.example; dmarc=pass header.from=spokeo.com.evil.example`,
			"spokeo.com", false},
		{"one failing and one aligned passing signature",
			`mx.google.com; dkim=fail header.d=spokeo.com; dkim=pass header.d=spokeo.com`,
			"spokeo.com", true},
		{"uppercase",
			`MX.GOOGLE.COM; DMARC=PASS header.from=Spokeo.COM`,
			"spokeo.com", true},
		{"no header", ``, "spokeo.com", false},
		{"no from domain", `mx.google.com; dmarc=pass header.from=spokeo.com`, "", false},
		{"comment containing dmarc=pass",
			`mx.google.com; spf=softfail (note: dmarc=pass header.from=spokeo.com) smtp.mailfrom=evil.example`,
			"spokeo.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Authenticated(tt.header, tt.from); got != tt.want {
				t.Errorf("Authenticated() = %v, want %v", got, tt.want)
			}
		})
	}
}
