package config

import (
	"reflect"
	"strings"
	"testing"
)

func fullProfile() Profile {
	return Profile{
		FirstName: "Jane", LastName: "Doe", Email: "jane@example.com",
		Address: "1 Main St", City: "Springfield", State: "CA", ZipCode: "90000",
		Country: "USA", Phone: "555-0100", DateOfBirth: "1990-01-01",
	}
}

func TestParseDisclosure(t *testing.T) {
	tests := []struct {
		in      []string
		want    Disclosure
		wantErr string
	}{
		{nil, Disclosure{}, ""},
		{[]string{"location"}, Disclosure{Location: true}, ""},
		{[]string{"street_address"}, Disclosure{Location: true, StreetAddress: true}, ""},
		{[]string{" Phone ", "DATE_OF_BIRTH"}, Disclosure{Phone: true, DateOfBirth: true}, ""},
		{[]string{"location", "location"}, Disclosure{Location: true}, ""},
		{[]string{"ssn"}, Disclosure{}, `unknown disclose value "ssn"`},
		{[]string{"name"}, Disclosure{}, "always included"},
	}
	for _, tt := range tests {
		got, err := ParseDisclosure(tt.in)
		if tt.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("ParseDisclosure(%v) err = %v, want %q", tt.in, err, tt.wantErr)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("ParseDisclosure(%v) = %+v, %v; want %+v", tt.in, got, err, tt.want)
		}
	}
}

func TestDisclosureApplyDefaultSendsNameAndEmailOnly(t *testing.T) {
	got := Disclosure{}.Apply(fullProfile())
	want := Profile{FirstName: "Jane", LastName: "Doe", Email: "jane@example.com"}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestDisclosureApplyEachField(t *testing.T) {
	p := fullProfile()
	if got := (Disclosure{Location: true}).Apply(p); got.City != "Springfield" || got.State != "CA" ||
		got.ZipCode != "90000" || got.Country != "USA" || got.Address != "" || got.Phone != "" || got.DateOfBirth != "" {
		t.Errorf("location: %+v", got)
	}
	if got := (Disclosure{Location: true, StreetAddress: true}).Apply(p); got.Address != "1 Main St" {
		t.Errorf("street_address: %+v", got)
	}
	if got := (Disclosure{Phone: true}).Apply(p); got.Phone != "555-0100" || got.City != "" {
		t.Errorf("phone: %+v", got)
	}
	if got := (Disclosure{DateOfBirth: true}).Apply(p); got.DateOfBirth != "1990-01-01" || got.Phone != "" {
		t.Errorf("date_of_birth: %+v", got)
	}
	all := Disclosure{Location: true, StreetAddress: true, Phone: true, DateOfBirth: true}
	if got := all.Apply(p); got != p {
		t.Errorf("all: %+v", got)
	}
}

func TestDisclosureUnion(t *testing.T) {
	a := Disclosure{Location: true}
	b := Disclosure{DateOfBirth: true}
	if got, want := a.Union(b), (Disclosure{Location: true, DateOfBirth: true}); got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestDisclosureFieldsAndWithheld(t *testing.T) {
	d := Disclosure{Location: true, Phone: true}
	if got, want := d.Fields(), []string{"name", "email", "location", "phone"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Fields() = %v, want %v", got, want)
	}
	if got, want := d.Withheld(fullProfile()), []string{"street_address", "date_of_birth"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Withheld() = %v, want %v", got, want)
	}
	if got := d.Withheld(Profile{FirstName: "J"}); len(got) != 0 {
		t.Errorf("Withheld(empty profile) = %v, want none", got)
	}
}

func TestValidateRejectsUnknownDisclose(t *testing.T) {
	cfg := &Config{
		Profile: Profile{FirstName: "J", LastName: "D", Email: "j@example.com"},
		Email:   EmailConfig{Provider: "smtp", From: "j@example.com", SMTP: SMTPConfig{Host: "h", Port: 465, UseTLS: true}},
		Options: Options{Disclose: []string{"passport"}},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "passport") {
		t.Fatalf("Validate() = %v, want unknown disclose error", err)
	}
}

func TestValidateRejectsUnknownTLSMode(t *testing.T) {
	cfg := &Config{
		Profile: Profile{FirstName: "J", LastName: "D", Email: "j@example.com"},
		Email:   EmailConfig{Provider: "smtp", From: "j@example.com", SMTP: SMTPConfig{Host: "h", Port: 587, UseTLS: true, TLSMode: "ssl"}},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "tls_mode") {
		t.Fatalf("Validate() = %v, want tls_mode error", err)
	}
}

func TestEffectiveTLSMode(t *testing.T) {
	tests := []struct {
		cfg  SMTPConfig
		want string
	}{
		{SMTPConfig{Port: 465, UseTLS: true}, TLSImplicit},
		{SMTPConfig{Port: 587, UseTLS: true}, TLSStartTLS},
		{SMTPConfig{Port: 2525, UseTLS: true, TLSMode: TLSImplicit}, TLSImplicit},
		{SMTPConfig{Port: 465, UseTLS: true, TLSMode: TLSStartTLS}, TLSStartTLS},
		{SMTPConfig{Port: 25, UseTLS: false}, TLSNone},
	}
	for _, tt := range tests {
		if got := tt.cfg.EffectiveTLSMode(); got != tt.want {
			t.Errorf("%+v: got %q, want %q", tt.cfg, got, tt.want)
		}
	}
}
