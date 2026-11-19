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
