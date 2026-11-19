package template

import (
	"strings"
	"testing"

	"github.com/eraser-privacy/eraser/internal/broker"
	"github.com/eraser-privacy/eraser/internal/config"
)

var profile = config.Profile{
	FirstName: "Jane", LastName: "Doe", Email: "jane@example.com",
	Address: "1 Main St", City: "Springfield", State: "CA", ZipCode: "90000",
	Country: "USA", Phone: "555-0100", DateOfBirth: "1990-01-01",
}

var acme = broker.Broker{ID: "acme", Name: "Acme Data", Email: "privacy@acme.example", Region: "us"}

func render(t *testing.T, tmpl string, d config.Disclosure, b broker.Broker) string {
	t.Helper()
	e, err := NewEngine()
	if err != nil {
		t.Fatal(err)
	}
	out, err := e.Render(tmpl, profile, d, b)
	if err != nil {
		t.Fatal(err)
	}
	return out.Body
}

func assertContains(t *testing.T, body string, want, notWant []string) {
	t.Helper()
	for _, s := range want {
		if !strings.Contains(body, s) {
			t.Errorf("body missing %q", s)
		}
	}
	for _, s := range notWant {
		if strings.Contains(body, s) {
			t.Errorf("body should not contain %q", s)
		}
	}
}

var (
	nameEmail = []string{"Jane Doe", "jane@example.com", "Acme Data"}
	location  = []string{"Springfield", "90000"}
	street    = []string{"1 Main St"}
	phone     = []string{"555-0100"}
	dob       = []string{"1990-01-01"}
)

func concat(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

func TestRenderDefaultDisclosesOnlyNameAndEmail(t *testing.T) {
	for _, tmpl := range []string{"generic", "gdpr", "ccpa"} {
		t.Run(tmpl, func(t *testing.T) {
			body := render(t, tmpl, config.Disclosure{}, acme)
			assertContains(t, body, nameEmail, concat(location, street, phone, dob))
		})
	}
}

func TestRenderGlobalDisclosure(t *testing.T) {
	body := render(t, "generic", config.Disclosure{Location: true, Phone: true}, acme)
	assertContains(t, body, concat(nameEmail, location, phone), concat(street, dob))
}

func TestRenderBrokerDisclosureAddsToGlobal(t *testing.T) {
	needsDOB := acme
	needsDOB.Disclose = []string{config.DiscloseDateOfBirth}

	body := render(t, "ccpa", config.Disclosure{Location: true}, needsDOB)
	assertContains(t, body, concat(nameEmail, location, dob), concat(street, phone))

	// The override applies only to that broker.
	body = render(t, "ccpa", config.Disclosure{Location: true}, acme)
	assertContains(t, body, concat(nameEmail, location), dob)
}

func TestRenderRejectsInvalidBrokerDisclosure(t *testing.T) {
	bad := acme
	bad.Disclose = []string{"ssn"}
	e, err := NewEngine()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Render("generic", profile, config.Disclosure{}, bad); err == nil {
		t.Fatal("expected error for invalid broker disclose value")
	}
}
