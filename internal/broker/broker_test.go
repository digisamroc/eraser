package broker

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func validBroker() Broker {
	return Broker{
		ID:       "acme-data",
		Name:     "Acme Data",
		Email:    "privacy@acmedata.com",
		Region:   "us",
		Category: "data-broker",
	}
}

func TestBrokerValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Broker)
		wantErr string
	}{
		{"valid", func(b *Broker) {}, ""},
		{"missing id", func(b *Broker) { b.ID = "" }, "id is required"},
		{"bad id chars", func(b *Broker) { b.ID = "Acme Data" }, "id"},
		{"missing name", func(b *Broker) { b.Name = "" }, "name is required"},
		{"missing email", func(b *Broker) { b.Email = "" }, "email"},
		{"display name email", func(b *Broker) { b.Email = "Acme <privacy@acmedata.com>" }, "email"},
		{"multiple recipients", func(b *Broker) { b.Email = "a@acmedata.com,b@acmedata.com" }, "email"},
		{"header injection", func(b *Broker) { b.Email = "a@acmedata.com\r\nBcc: x@evil.com" }, "email"},
		{"gmail", func(b *Broker) { b.Email = "acmedata@gmail.com" }, "personal mailbox"},
		{"hotmail mixed case", func(b *Broker) { b.Email = "Acme@HotMail.com" }, "personal mailbox"},
		{"unknown region", func(b *Broker) { b.Region = "mars" }, "region"},
		{"unknown category", func(b *Broker) { b.Category = "spies" }, "category"},
		{"empty category ok", func(b *Broker) { b.Category = "" }, ""},
		{"valid disclose", func(b *Broker) { b.Disclose = []string{"date_of_birth"} }, ""},
		{"invalid disclose", func(b *Broker) { b.Disclose = []string{"ssn"} }, "disclose"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := validBroker()
			tt.mutate(&b)
			err := b.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("got %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestDatabaseValidateDuplicateID(t *testing.T) {
	a, b := validBroker(), validBroker()
	b.Email = "other@acmedata.com"
	db := &BrokerDatabase{Brokers: []Broker{a, b}}
	if err := db.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate id") {
		t.Fatalf("got %v, want duplicate id error", err)
	}
}

func TestLoadFromFileRejectsInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "brokers.yaml")
	data := "brokers:\n  - id: bad\n    name: Bad\n    email: bad@gmail.com\n    region: us\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFromFile(path); err == nil {
		t.Fatal("expected LoadFromFile to reject a personal-mailbox broker")
	}
}

func TestShippedBrokerDatabaseIsValid(t *testing.T) {
	if _, err := LoadFromFile("../../data/brokers.yaml"); err != nil {
		t.Fatalf("data/brokers.yaml: %v", err)
	}
}

func TestFilterRegions(t *testing.T) {
	db := &BrokerDatabase{Brokers: []Broker{
		{ID: "us1", Region: "us"},
		{ID: "eu1", Region: "eu"},
		{ID: "gl1", Region: "global"},
	}}
	tests := []struct {
		regions []string
		want    []string
	}{
		{nil, []string{"us1", "eu1", "gl1"}},
		{[]string{"us"}, []string{"us1", "gl1"}},
		{[]string{"us", "global"}, []string{"us1", "gl1"}},
		{[]string{"eu"}, []string{"eu1", "gl1"}},
		{[]string{"global"}, []string{"gl1"}},
	}
	for _, tt := range tests {
		got := ids(db.Filter(tt.regions, nil))
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("Filter(%v) = %v, want %v", tt.regions, got, tt.want)
		}
	}
}

func TestFilterExclusionsAndFormOnly(t *testing.T) {
	db := &BrokerDatabase{Brokers: []Broker{
		{ID: "keep", Name: "Keep", Region: "us"},
		{ID: "by-id", Name: "By ID", Region: "us"},
		{ID: "by-name", Name: "By Name", Region: "us"},
		{ID: "form", Name: "Form", Region: "us", Tags: []string{TagFormOnly}},
	}}
	got := ids(db.Filter(nil, []string{"BY-ID", "by name"}))
	if want := []string{"keep"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestOwnsURL(t *testing.T) {
	b := Broker{
		ID: "acme", Email: "privacy@acme.com", Website: "https://www.acmedata.com",
		OptOutURL: "https://privacyportal.onetrust.com/webform/abc-123",
	}
	tests := map[string]bool{
		"https://acme.com/opt-out":                                        true,
		"https://privacy.acme.com/dsr?x=1":                                true,
		"https://www.acmedata.com/remove":                                 true,
		"https://ACMEDATA.com:443/remove":                                 true,
		"https://privacyportal.onetrust.com/webform/abc-123":              true,
		"https://privacyportal.onetrust.com/webform/abc-123/step2":        true,
		"https://privacyportal.onetrust.com/webform/abc-1234":             false, // not under the registered path
		"https://privacyportal.onetrust.com/webform/other":                false, // someone else's form on the same platform
		"https://privacyportal.onetrust.com/webform/abc-123/../other":     false, // browsers resolve ".."
		"https://privacyportal.onetrust.com/webform/abc-123/%2e%2e/other": false,
		"http://acme.com/opt-out":                                         false, // never send PII over plain HTTP
		"https://acme.com.evil.example/opt-out":                           false,
		"https://evilacme.com/opt-out":                                    false,
		"https://evil.example/?next=https://acme.com":                     false,
		"javascript:alert(1)":                                             false,
		"":                                                                false,
	}
	for raw, want := range tests {
		if got := b.OwnsURL(raw); got != want {
			t.Errorf("OwnsURL(%q) = %v, want %v", raw, got, want)
		}
	}

	// A personal mailbox domain never vouches for a URL.
	gmail := Broker{ID: "x", Email: "someone@gmail.com"}
	if gmail.OwnsURL("https://mail.gmail.com/form") {
		t.Error("gmail.com URL accepted for a broker with a gmail address")
	}
}

// A broker whose email is on a help desk's subdomain (privacy@acme.zendesk.com)
// owns that subdomain, not the whole help desk: other customers' pages there
// aren't the broker's. Its own email subdomains still cover the organization.
func TestOwnsURLHelpDeskEmail(t *testing.T) {
	helpDesk := Broker{ID: "acme", Email: "privacy@acme.zendesk.com", Website: "https://www.acme.com"}
	for raw, want := range map[string]bool{
		"https://acme.zendesk.com/hc/requests/new": true,
		"https://help.acme.zendesk.com/form":       true,
		"https://www.acme.com/privacy":             true,
		"https://other.zendesk.com/hc/requests":    false,
		"https://zendesk.com/form":                 false,
	} {
		if got := helpDesk.OwnsURL(raw); got != want {
			t.Errorf("help desk: OwnsURL(%q) = %v, want %v", raw, got, want)
		}
	}

	noWebsite := Broker{ID: "acme", Email: "privacy@acme.zendesk.com"}
	if noWebsite.OwnsURL("https://other.zendesk.com/hc") {
		t.Error("no website: another help desk customer's page accepted")
	}

	ownSubdomain := Broker{ID: "acme", Email: "privacy@mail.acme.com", Website: "https://www.acme.com"}
	if !ownSubdomain.OwnsURL("https://privacy.acme.com/form") {
		t.Error("own email subdomain no longer covers the broker's organization")
	}
}

func TestEmailAccepted(t *testing.T) {
	if !(Broker{}).EmailAccepted() {
		t.Error("broker without tags should accept email")
	}
	if (Broker{Tags: []string{"x", TagFormOnly}}).EmailAccepted() {
		t.Error("form-only broker should not accept email")
	}
}

func ids(bs []Broker) []string {
	out := make([]string, len(bs))
	for i, b := range bs {
		out[i] = b.ID
	}
	return out
}
