package registry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eraser-privacy/eraser/internal/broker"
)

const manualFixture = `# Hand-maintained overlay. Keep this comment.

add: []

overrides:
  # Reported in upstream PR #29.
  - email: privacy@epsilon.com
    tags: [form-only]
    source_url: https://github.com/digisamroc/eraser/pull/29

exclude: []
`

func writeManual(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "brokers.manual.yaml")
	if err := os.WriteFile(path, []byte(manualFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAddToManualKeepsCommentsAndValidates(t *testing.T) {
	path := writeManual(t)
	b := broker.Broker{ID: "people-finder", Name: "People Finder", Email: "privacy@peoplefinder.example",
		Region: "us", Category: "people-search", SourceURL: "https://peoplefinder.example/privacy"}
	if err := AddToManual(path, b); err != nil {
		t.Fatal(err)
	}

	raw, _ := os.ReadFile(path) //nolint:gosec // G304: test temp file
	text := string(raw)
	for _, keep := range []string{"# Hand-maintained overlay. Keep this comment.", "# Reported in upstream PR #29."} {
		if !strings.Contains(text, keep) {
			t.Errorf("lost comment %q:\n%s", keep, text)
		}
	}
	m, err := LoadManual(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Add) != 1 || m.Add[0].ID != "people-finder" || len(m.Overrides) != 1 {
		t.Fatalf("manual = %+v", m)
	}

	// Entries the build would reject are refused up front.
	bad := b
	bad.ID, bad.SourceURL = "no-source", ""
	if err := AddToManual(path, bad); err == nil {
		t.Error("accepted an entry without source_url")
	}
	bad = b
	bad.ID, bad.Email = "gmail-broker", "x@gmail.com"
	if err := AddToManual(path, bad); err == nil {
		t.Error("accepted a personal mailbox")
	}
}

func TestExcludeInManual(t *testing.T) {
	path := writeManual(t)
	xs := []Exclusion{
		{Email: "old@acme.example", Reason: "Bounced: address not found", Evidence: "bounce notification received 2026-11-19"},
	}
	if err := ExcludeInManual(path, xs); err != nil {
		t.Fatal(err)
	}
	m, err := LoadManual(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Exclude) != 1 || m.Exclude[0].Evidence == "" {
		t.Fatalf("exclude = %+v", m.Exclude)
	}
	if err := ExcludeInManual(path, []Exclusion{{Email: "x@acme.example", Reason: "no source"}}); err == nil {
		t.Error("accepted an exclusion with neither source_url nor evidence")
	}
}

func TestWriteDatabaseRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "brokers.yaml")
	db := &broker.BrokerDatabase{Brokers: []broker.Broker{
		{ID: "zeta", Name: "Zeta", Email: "p@zeta.example", Region: "us"},
		{ID: "alpha", Name: "Alpha", Email: "p@alpha.example", Region: "us"},
	}}
	if err := WriteDatabase(path, db); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path) //nolint:gosec // G304: test temp file
	if !strings.HasPrefix(string(raw), "# GENERATED") {
		t.Errorf("missing generated header:\n%s", raw)
	}
	got, err := broker.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Brokers[0].ID != "alpha" {
		t.Errorf("not sorted by name: %v", got.Brokers)
	}
}
