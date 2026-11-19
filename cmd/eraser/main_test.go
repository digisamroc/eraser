package main

import (
	"bufio"
	"bytes"
	"net/url"
	"strings"
	"testing"

	"github.com/eraser-privacy/eraser/internal/broker"
	"github.com/eraser-privacy/eraser/internal/config"
)

func TestFillProfileAppliesDisclosure(t *testing.T) {
	cfg := &config.Config{
		Profile: config.Profile{FirstName: "J", LastName: "D", Email: "j@example.com",
			Address: "1 Main", City: "Town", Phone: "555", DateOfBirth: "1990-01-01"},
		Options: config.Options{Disclose: []string{"location"}},
	}
	b := &broker.Broker{ID: "acme", Disclose: []string{"date_of_birth"}}

	p, err := fillProfile(cfg, b)
	if err != nil {
		t.Fatal(err)
	}
	if p.City != "Town" || p.DateOfBirth != "1990-01-01" || p.Phone != "" || p.Address != "" {
		t.Fatalf("profile = %+v", p)
	}

	// Without a broker (a URL the user typed), only the global setting applies.
	p, err = fillProfile(cfg, nil)
	if err != nil || p.DateOfBirth != "" || p.City != "Town" {
		t.Fatalf("profile = %+v, err = %v", p, err)
	}
}

func TestTypedURLAllowed(t *testing.T) {
	allowed, err := typedURLAllowed("https://forms.example.com/opt-out")
	if err != nil {
		t.Fatal(err)
	}
	for raw, want := range map[string]bool{
		"https://forms.example.com/opt-out": true,
		"https://www.example.com/done":      true, // same site
		"http://forms.example.com/opt-out":  false,
		"https://example.org/opt-out":       false,
		"https://example.com.evil.test/":    false,
	} {
		u, _ := url.Parse(raw)
		if got := allowed(u); got != want {
			t.Errorf("allowed(%q) = %v, want %v", raw, got, want)
		}
	}
	if _, err := typedURLAllowed("http://forms.example.com/opt-out"); err == nil {
		t.Error("plain-HTTP form URL accepted")
	}
}

func TestConfirmSend(t *testing.T) {
	fields := []string{"name", "email"}
	tests := []struct {
		name        string
		input       string
		interactive bool
		wantErr     string
	}{
		{"yes", "yes\n", true, ""},
		{"YES with spaces", "  YES \n", true, ""},
		{"y is not enough", "y\n", true, "cancelled"},
		{"empty", "\n", true, "cancelled"},
		{"eof", "", true, "cancelled"},
		{"not a terminal", "yes\n", false, "--yes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			err := confirmSend(strings.NewReader(tt.input), &out, tt.interactive, 42, fields)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !strings.Contains(out.String(), "42 brokers") || !strings.Contains(out.String(), "name, email") {
					t.Errorf("prompt should state count and disclosed fields: %q", out.String())
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("got %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestPromptSMTP(t *testing.T) {
	// Blank answers keep the Gmail defaults.
	got := promptSMTP(bufio.NewReader(strings.NewReader("\n\njane@gmail.com\napp-pw\n")))
	want := config.SMTPConfig{Host: "smtp.gmail.com", Port: 465, Username: "jane@gmail.com", Password: "app-pw", UseTLS: true}
	if got != want {
		t.Errorf("defaults: got %+v, want %+v", got, want)
	}

	// Any server works; a bad port is asked again.
	got = promptSMTP(bufio.NewReader(strings.NewReader("mail.privateemail.com\n70000\nabc\n587\njane@example.com\npw\n")))
	want = config.SMTPConfig{Host: "mail.privateemail.com", Port: 587, Username: "jane@example.com", Password: "pw", UseTLS: true}
	if got != want {
		t.Errorf("custom: got %+v, want %+v", got, want)
	}
}
