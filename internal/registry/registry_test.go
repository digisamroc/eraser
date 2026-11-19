package registry

import (
	"strings"
	"testing"

	"github.com/eraser-privacy/eraser/internal/broker"
)

// Header names copied from the CPPA 2026 export (abbreviated tail columns).
var csvHeader = string(rune(0xFEFF)) + "Broker ID,Data broker name:,\"Doing Business As (DBA), if applicable:\"," +
	"Data broker primary website:,Data broker primary contact email address:," +
	"Data broker primary phone number: [optional]," +
	"Data broker's primary website that contains details on how consumers can exercise their CA Consumer Privacy rights:," +
	"Data broker collects personal information of minors:\n"

func parse(t *testing.T, rows string) []Entry {
	t.Helper()
	entries, err := ParseCSV(strings.NewReader(csvHeader + rows))
	if err != nil {
		t.Fatalf("ParseCSV: %v", err)
	}
	return entries
}

func TestParseCSV(t *testing.T) {
	entries := parse(t, "1001,\"Acme Data, Inc.\",Acme,https://acme.com, Privacy@Acme.com ,555,https://acme.com/privacy,No\n")
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	want := Entry{
		RegistryID: "1001", Name: "Acme Data, Inc.", DBA: "Acme",
		Website: "https://acme.com", Email: " Privacy@Acme.com ", PrivacyURL: "https://acme.com/privacy",
	}
	if entries[0] != want {
		t.Fatalf("got %+v\nwant %+v", entries[0], want)
	}
}

func TestParseCSVMissingColumn(t *testing.T) {
	header := strings.Replace(csvHeader, "Data broker primary contact email address:,", "", 1)
	_, err := ParseCSV(strings.NewReader(header))
	if err == nil || !strings.Contains(err.Error(), "email") {
		t.Fatalf("got %v, want missing email column error", err)
	}
}

func build(t *testing.T, entries []Entry, m Manual) (*broker.BrokerDatabase, Report) {
	t.Helper()
	db, rep, err := Build(entries, m, Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return db, rep
}

func TestBuildNormalizesAndNames(t *testing.T) {
	db, _ := build(t, []Entry{
		{RegistryID: "1", Name: "Acme Data, Inc.", DBA: "Acme People Search", Email: " Privacy [at] Acme.COM ", Website: "https://acme.com", PrivacyURL: "https://acme.com/privacy"},
		{RegistryID: "2", Name: "Beta Holdings LLC", DBA: "N/A", Email: "dpo@beta.io", PrivacyURL: "javascript:alert(1)"},
	}, Manual{})

	if len(db.Brokers) != 2 {
		t.Fatalf("got %d brokers", len(db.Brokers))
	}
	a, b := db.Brokers[0], db.Brokers[1]
	if a.ID != "acme-people-search" || a.Name != "Acme People Search" || a.Email != "privacy@acme.com" {
		t.Errorf("acme: %+v", a)
	}
	if a.Website != "https://acme.com" {
		t.Errorf("acme website: %q", a.Website)
	}
	if !strings.Contains(a.Notes, "Acme Data, Inc.") {
		t.Errorf("acme notes should mention legal name: %q", a.Notes)
	}
	if a.OptOutURL != "https://acme.com/privacy" || a.Source != SourceCPPA || a.RegistryID != "1" || a.Region != "us" || a.Category != "data-broker" {
		t.Errorf("acme fields: %+v", a)
	}
	if b.ID != "beta-holdings" || b.Name != "Beta Holdings LLC" || b.OptOutURL != "" {
		t.Errorf("beta: %+v", b)
	}
}

func TestBuildListDBAUsesLegalName(t *testing.T) {
	db, _ := build(t, []Entry{{
		RegistryID: "7", Name: "Spokeo, Inc.", Email: "privacy@spokeo.com",
		DBA:     "Spokeo.com, FreePeopleDirectory.com, ThatsThem.com",
		Website: "spokeo.com; thatsthem.com",
	}}, Manual{})
	b := db.Brokers[0]
	if b.ID != "spokeo" || b.Name != "Spokeo, Inc." {
		t.Errorf("id/name = %q/%q", b.ID, b.Name)
	}
	if !strings.Contains(b.Notes, "ThatsThem.com") {
		t.Errorf("notes should keep the DBA list: %q", b.Notes)
	}
	if b.Website != "https://spokeo.com" {
		t.Errorf("website = %q", b.Website)
	}
}

func TestNormalizeURL(t *testing.T) {
	tests := map[string]string{
		"https://acme.com/privacy":        "https://acme.com/privacy",
		"http://acme.com":                 "http://acme.com",
		" www.epsilon.com ":               "https://www.epsilon.com",
		"acronymix.com":                   "https://acronymix.com",
		"infopay.com; infotracer.com":     "https://infopay.com",
		"a.com, b.com":                    "https://a.com",
		"javascript:alert(1)":             "",
		"ftp://acme.com":                  "",
		"not a url":                       "",
		"":                                "",
		"localhost":                       "",
		"https://":                        "",
		"https://acme.com/a b":            "",
		"HTTPS://Acme.com/Privacy-Choice": "HTTPS://Acme.com/Privacy-Choice",
	}
	for in, want := range tests {
		if got := normalizeURL(in); got != want {
			t.Errorf("normalizeURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildRejectsFreemailAndInvalid(t *testing.T) {
	db, rep := build(t, []Entry{
		{RegistryID: "1", Name: "Good Co", Email: "privacy@good.com"},
		{RegistryID: "2", Name: "Gmail Co", Email: "goodco@gmail.com"},
		{RegistryID: "3", Name: "Broken Co", Email: "not an email"},
	}, Manual{})
	if len(db.Brokers) != 1 || db.Brokers[0].ID != "good" {
		t.Fatalf("got %+v", db.Brokers)
	}
	if len(rep.Rejected) != 2 {
		t.Fatalf("rejected = %v, want 2 entries", rep.Rejected)
	}
}

func TestBuildMergesDuplicateEmails(t *testing.T) {
	db, rep := build(t, []Entry{
		{RegistryID: "1", Name: "TransUnion LLC", Email: "privacy@tu.com"},
		{RegistryID: "2", Name: "TransUnion Marketing", Email: "PRIVACY@tu.com"},
	}, Manual{})
	if len(db.Brokers) != 1 {
		t.Fatalf("got %d brokers, want 1", len(db.Brokers))
	}
	if !strings.Contains(db.Brokers[0].Notes, "TransUnion Marketing") {
		t.Errorf("notes should list merged registration: %q", db.Brokers[0].Notes)
	}
	if rep.Merged != 1 {
		t.Errorf("merged = %d, want 1", rep.Merged)
	}
}

func TestBuildIDCollision(t *testing.T) {
	db, _ := build(t, []Entry{
		{RegistryID: "10", Name: "Acme Inc", Email: "a@acme.com"},
		{RegistryID: "11", Name: "Acme LLC", Email: "b@acme.net"},
	}, Manual{})
	if db.Brokers[0].ID != "acme" || db.Brokers[1].ID != "acme-11" {
		t.Fatalf("ids = %s, %s", db.Brokers[0].ID, db.Brokers[1].ID)
	}
}

func TestBuildManualExcludeAndOverride(t *testing.T) {
	entries := []Entry{
		{RegistryID: "1", Name: "Keep Co", Email: "privacy@keep.com"},
		{RegistryID: "2", Name: "Drop Co", Email: "privacy@drop.com"},
		{RegistryID: "3", Name: "Form Co", Email: "privacy@form.com"},
	}
	m := Manual{
		Exclude: []Exclusion{{Email: "privacy@drop.com", Reason: "bounces", SourceURL: "https://example.com/report"}},
		Overrides: []Override{{
			Email: "PRIVACY@form.com", Tags: []string{broker.TagFormOnly}, Category: "people-search",
			OptOutURL: "https://form.com/dsr", Notes: "Email not processed.", SourceURL: "https://example.com/report",
		}, {
			Email: "privacy@gone.com", Notes: "stale", SourceURL: "https://example.com/report",
		}},
	}
	db, rep := build(t, entries, m)
	if len(db.Brokers) != 2 {
		t.Fatalf("got %d brokers, want 2", len(db.Brokers))
	}
	form := db.FindByEmail("privacy@form.com")
	if form == nil || form.EmailAccepted() || form.Category != "people-search" || form.OptOutURL != "https://form.com/dsr" {
		t.Fatalf("override not applied: %+v", form)
	}
	if !strings.Contains(form.Notes, "Email not processed.") {
		t.Errorf("notes: %q", form.Notes)
	}
	if len(rep.Excluded) != 1 || len(rep.Warnings) != 1 || !strings.Contains(rep.Warnings[0], "privacy@gone.com") {
		t.Fatalf("report: %+v", rep)
	}
}

func TestBuildManualAdd(t *testing.T) {
	add := broker.Broker{ID: "people-finder", Name: "People Finder", Email: "privacy@peoplefinder.example", Region: "us", Category: "people-search", SourceURL: "https://peoplefinder.example/privacy"}
	db, _ := build(t, []Entry{{RegistryID: "1", Name: "Keep Co", Email: "privacy@keep.com"}}, Manual{Add: []broker.Broker{add}})
	got := db.FindByID("people-finder")
	if got == nil || got.Source != SourceManual {
		t.Fatalf("manual add missing or unmarked: %+v", got)
	}
}

func TestBuildManualErrors(t *testing.T) {
	entries := []Entry{{RegistryID: "1", Name: "Keep Co", Email: "privacy@keep.com"}}
	ok := broker.Broker{ID: "x", Name: "X", Email: "privacy@x.example", Region: "us", SourceURL: "https://x.example/privacy"}

	tests := map[string]Manual{
		"add without source":       {Add: []broker.Broker{func() broker.Broker { b := ok; b.SourceURL = ""; return b }()}},
		"add with http source":     {Add: []broker.Broker{func() broker.Broker { b := ok; b.SourceURL = "http://x.example"; return b }()}},
		"add duplicates registry":  {Add: []broker.Broker{func() broker.Broker { b := ok; b.Email = "privacy@keep.com"; return b }()}},
		"add freemail":             {Add: []broker.Broker{func() broker.Broker { b := ok; b.Email = "x@gmail.com"; return b }()}},
		"exclude without reason":   {Exclude: []Exclusion{{Email: "privacy@keep.com", SourceURL: "https://x.example"}}},
		"override without source":  {Overrides: []Override{{Email: "privacy@keep.com", Notes: "n"}}},
		"override invalid tag":     {Overrides: []Override{{Email: "privacy@keep.com", Tags: []string{"bogus"}, SourceURL: "https://x.example"}}},
		"override bad opt-out url": {Overrides: []Override{{Email: "privacy@keep.com", OptOutURL: "javascript:x", SourceURL: "https://x.example"}}},
	}
	for name, m := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Build(entries, m, Options{}); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestBuildMXCheck(t *testing.T) {
	entries := []Entry{
		{RegistryID: "1", Name: "Live Co", Email: "privacy@live.example"},
		{RegistryID: "2", Name: "Dead Co", Email: "privacy@dead.example"},
	}
	opts := Options{HasMailHost: func(domain string) bool { return domain == "live.example" }}
	db, rep, err := Build(entries, Manual{}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(db.Brokers) != 1 || db.Brokers[0].ID != "live" || len(rep.NoMailHost) != 1 {
		t.Fatalf("brokers=%+v report=%+v", db.Brokers, rep)
	}
}

func TestSlug(t *testing.T) {
	tests := map[string]string{
		"Acme Data, Inc.":         "acme-data",
		"Trans Union LLC":         "trans-union",
		"eXelate, Inc.":           "exelate",
		"L.L. Bean Co.":           "l-l-bean",
		"33Across, Inc.":          "33across",
		"Société Générale S.A.":   "soci-t-g-n-rale-s-a",
		"Inc.":                    "inc",
		"Data & Analytics Corp":   "data-analytics",
		"  Spaces   Everywhere  ": "spaces-everywhere",
	}
	for in, want := range tests {
		if got := slug(in); got != want {
			t.Errorf("slug(%q) = %q, want %q", in, got, want)
		}
	}
}
