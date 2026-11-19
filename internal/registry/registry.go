// Package registry builds the broker database from the California Privacy
// Protection Agency (CPPA) data broker registry plus a small hand-maintained
// overlay file. Brokers register their own contact details with the state, so
// every generated entry is backed by an official record.
package registry

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/eraser-privacy/eraser/internal/broker"
	"github.com/eraser-privacy/eraser/internal/config"
	"gopkg.in/yaml.v3"
)

const (
	// RegistryURL is the CPPA's current data broker registry export.
	RegistryURL = "https://cppa.ca.gov/data_broker_registry/registry.csv"
	// RegistryPage is the human-readable page cited as each entry's source.
	RegistryPage = "https://cppa.ca.gov/data_broker_registry/"

	SourceCPPA   = "ca-cppa"
	SourceManual = "manual"
)

// Entry is one row of the registry, with only the fields Eraser uses.
type Entry struct {
	RegistryID string
	Name       string
	DBA        string
	Website    string
	Email      string
	PrivacyURL string
}

// Column headers are matched by prefix because the CPPA appends punctuation
// and long explanatory text to them.
var columns = []struct {
	prefix string
	label  string
	set    func(*Entry, string)
}{
	{"Broker ID", "broker id", func(e *Entry, v string) { e.RegistryID = v }},
	{"Data broker name", "name", func(e *Entry, v string) { e.Name = v }},
	{"Doing Business As", "dba", func(e *Entry, v string) { e.DBA = v }},
	{"Data broker primary website", "website", func(e *Entry, v string) { e.Website = v }},
	{"Data broker primary contact email", "email", func(e *Entry, v string) { e.Email = v }},
	{"Data broker's primary website that contains details on how consumers can exercise", "privacy rights url", func(e *Entry, v string) { e.PrivacyURL = v }},
}

// ParseCSV reads a CPPA registry export.
func ParseCSV(r io.Reader) ([]Entry, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1

	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read registry header: %w", err)
	}

	index := make([]int, len(columns))
	for i, col := range columns {
		index[i] = -1
		for j, h := range header {
			h = strings.TrimSpace(strings.TrimPrefix(h, bom))
			if strings.HasPrefix(h, col.prefix) {
				index[i] = j
				break
			}
		}
		if index[i] == -1 {
			return nil, fmt.Errorf("registry is missing the %s column (header starting %q)", col.label, col.prefix)
		}
	}

	var entries []Entry
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read registry row: %w", err)
		}
		var e Entry
		for i, col := range columns {
			if index[i] < len(rec) {
				col.set(&e, rec[index[i]])
			}
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// Manual is the hand-maintained overlay applied on top of the registry.
// Every item must cite an https source so changes can be checked later.
type Manual struct {
	Add       []broker.Broker `yaml:"add"`
	Overrides []Override      `yaml:"overrides"`
	Exclude   []Exclusion     `yaml:"exclude"`
}

// Override adjusts a registry entry, matched by email address.
type Override struct {
	Email     string   `yaml:"email"`
	Category  string   `yaml:"category,omitempty"`
	OptOutURL string   `yaml:"opt_out_url,omitempty"`
	Tags      []string `yaml:"tags,omitempty"`
	Disclose  []string `yaml:"disclose,omitempty"` // extra profile fields this broker needs
	Notes     string   `yaml:"notes,omitempty"`
	SourceURL string   `yaml:"source_url"`
}

// Exclusion drops a registry entry, matched by email address. It needs a
// reason and either an https source_url or, for local evidence such as a
// bounce notification, an evidence note.
type Exclusion struct {
	Email     string `yaml:"email"`
	Reason    string `yaml:"reason"`
	SourceURL string `yaml:"source_url,omitempty"`
	Evidence  string `yaml:"evidence,omitempty"`
}

// LoadManual reads the overlay file.
func LoadManual(path string) (Manual, error) {
	var m Manual
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is the operator's -manual flag
	if err != nil {
		return m, fmt.Errorf("failed to read %s: %w", path, err)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil && !errors.Is(err, io.EOF) {
		return m, fmt.Errorf("failed to parse %s: %w", path, err)
	}
	return m, nil
}

// Options controls optional checks during Build.
type Options struct {
	// HasMailHost reports whether a domain can receive mail. Nil skips the check.
	HasMailHost func(domain string) bool
}

// Report summarizes what Build kept and dropped.
type Report struct {
	Rows       int
	Merged     int
	Rejected   []string
	Excluded   []string
	NoMailHost []string
	Overridden int
	Added      int
	Warnings   []string
}

var allowedOverrideTags = map[string]bool{broker.TagFormOnly: true}

// Build turns registry entries plus the manual overlay into a validated database.
func Build(entries []Entry, m Manual, opts Options) (*broker.BrokerDatabase, Report, error) {
	rep := Report{Rows: len(entries)}
	if err := m.validate(); err != nil {
		return nil, rep, err
	}

	excluded := make(map[string]Exclusion, len(m.Exclude))
	for _, x := range m.Exclude {
		excluded[normalizeEmail(x.Email)] = x
	}

	var brokers []broker.Broker
	byEmail := make(map[string]int)
	ids := make(map[string]bool)

	for _, e := range entries {
		email := normalizeEmail(e.Email)
		label := fmt.Sprintf("%s (registry %s)", strings.TrimSpace(e.Name), e.RegistryID)

		if err := broker.ValidateEmail(email); err != nil {
			rep.Rejected = append(rep.Rejected, fmt.Sprintf("%s: %v", label, err))
			continue
		}
		if x, ok := excluded[email]; ok {
			rep.Excluded = append(rep.Excluded, fmt.Sprintf("%s: %s", label, x.Reason))
			continue
		}

		legal, dba := strings.TrimSpace(e.Name), cleanDBA(e.DBA)
		if i, ok := byEmail[email]; ok {
			brokers[i].Notes = appendNote(brokers[i].Notes, "Also registered as "+displayName(legal, dba)+" (registry "+e.RegistryID+").")
			rep.Merged++
			continue
		}

		if opts.HasMailHost != nil && !opts.HasMailHost(domainOf(email)) {
			rep.NoMailHost = append(rep.NoMailHost, fmt.Sprintf("%s: %s", label, email))
			continue
		}

		b := broker.Broker{
			ID:         uniqueID(slug(displayName(legal, dba)), e.RegistryID, ids),
			Name:       displayName(legal, dba),
			Email:      email,
			Website:    normalizeURL(e.Website),
			OptOutURL:  normalizeURL(e.PrivacyURL),
			Region:     "us",
			Category:   "data-broker",
			Source:     SourceCPPA,
			SourceURL:  RegistryPage,
			RegistryID: e.RegistryID,
		}
		switch {
		case dba != "" && isDBAList(dba):
			b.Notes = "Doing business as " + dba + "."
		case dba != "" && dba != legal:
			b.Notes = "Registered as " + legal + "."
		}
		byEmail[email] = len(brokers)
		brokers = append(brokers, b)
	}

	for _, o := range m.Overrides {
		i, ok := byEmail[normalizeEmail(o.Email)]
		if !ok {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("override for %s matches no registry entry; remove it from the manual file", o.Email))
			continue
		}
		b := &brokers[i]
		if o.Category != "" {
			b.Category = o.Category
		}
		if o.OptOutURL != "" {
			b.OptOutURL = normalizeURL(o.OptOutURL)
		}
		for _, t := range o.Tags {
			if !slices.Contains(b.Tags, t) {
				b.Tags = append(b.Tags, t)
			}
		}
		for _, d := range o.Disclose {
			if !slices.Contains(b.Disclose, d) {
				b.Disclose = append(b.Disclose, d)
			}
		}
		b.Notes = appendNote(b.Notes, o.Notes)
		rep.Overridden++
	}

	for _, a := range m.Add {
		a.Email = normalizeEmail(a.Email)
		if _, dup := byEmail[a.Email]; dup {
			return nil, rep, fmt.Errorf("manual broker %s uses %s, which is already in the registry; use an override instead", a.ID, a.Email)
		}
		if ids[a.ID] {
			return nil, rep, fmt.Errorf("manual broker id %q collides with a registry entry", a.ID)
		}
		a.Source = SourceManual
		ids[a.ID] = true
		byEmail[a.Email] = len(brokers)
		brokers = append(brokers, a)
		rep.Added++
	}

	sort.SliceStable(brokers, func(i, j int) bool {
		return strings.ToLower(brokers[i].Name) < strings.ToLower(brokers[j].Name)
	})

	db := &broker.BrokerDatabase{Brokers: brokers}
	if err := db.Validate(); err != nil {
		return nil, rep, fmt.Errorf("generated database is invalid: %w", err)
	}
	return db, rep, nil
}

func (m Manual) validate() error {
	for _, a := range m.Add {
		if err := requireSource(a.SourceURL); err != nil {
			return fmt.Errorf("manual broker %s: %w", a.ID, err)
		}
		a.Email = normalizeEmail(a.Email)
		if err := a.Validate(); err != nil {
			return fmt.Errorf("manual broker: %w", err)
		}
	}
	for _, o := range m.Overrides {
		if err := requireSource(o.SourceURL); err != nil {
			return fmt.Errorf("override for %s: %w", o.Email, err)
		}
		for _, t := range o.Tags {
			if !allowedOverrideTags[t] {
				return fmt.Errorf("override for %s: unknown tag %q", o.Email, t)
			}
		}
		if _, err := config.ParseDisclosure(o.Disclose); err != nil {
			return fmt.Errorf("override for %s: %w", o.Email, err)
		}
		if o.OptOutURL != "" && normalizeURL(o.OptOutURL) == "" {
			return fmt.Errorf("override for %s: opt_out_url must be http(s)", o.Email)
		}
		probe := broker.Broker{ID: "probe", Name: "probe", Email: "probe@example.com", Region: "us", Category: o.Category}
		if err := probe.Validate(); err != nil {
			return fmt.Errorf("override for %s: unknown category %q", o.Email, o.Category)
		}
	}
	for _, x := range m.Exclude {
		if strings.TrimSpace(x.Reason) == "" {
			return fmt.Errorf("exclusion for %s: reason is required", x.Email)
		}
		if strings.TrimSpace(x.Evidence) == "" {
			if err := requireSource(x.SourceURL); err != nil {
				return fmt.Errorf("exclusion for %s: needs an https source_url or an evidence note", x.Email)
			}
		}
	}
	return nil
}

func requireSource(raw string) error {
	u, err := url.Parse(raw)
	if raw == "" || err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("source_url must be an https URL citing where the information came from")
	}
	return nil
}

const bom = "\uFEFF"

var obfuscatedAt = regexp.MustCompile(`(?i)\s*[\[(]\s*at\s*[\])]\s*`)

func normalizeEmail(s string) string {
	s = obfuscatedAt.ReplaceAllString(s, "@")
	return strings.ToLower(strings.TrimSpace(s))
}

func domainOf(email string) string {
	return email[strings.LastIndex(email, "@")+1:]
}

// cleanDBA drops placeholder values registrants use for "no DBA".
func cleanDBA(s string) string {
	s = strings.TrimSpace(s)
	switch strings.ToLower(strings.Trim(s, ".")) {
	case "", "n/a", "na", "none", "not applicable", "-":
		return ""
	}
	return s
}

// displayName prefers a single trading name over the legal name. Some
// registrants list every site they run as their DBA; those keep the legal name.
func displayName(legal, dba string) string {
	if dba != "" && !isDBAList(dba) {
		return dba
	}
	return legal
}

func isDBAList(dba string) bool {
	return strings.ContainsAny(dba, ",;") || len(dba) > 60
}

func appendNote(notes, add string) string {
	add = strings.TrimSpace(add)
	switch {
	case add == "":
		return notes
	case notes == "":
		return add
	default:
		return notes + " " + add
	}
}

var urlListSeparator = regexp.MustCompile(`[;,\s]+`)

// normalizeURL returns an http(s) URL, or "" if raw isn't one. Registrants
// often omit the scheme ("www.acme.com") or list several sites; the first is used.
func normalizeURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.ContainsAny(raw, ";,") {
		raw = urlListSeparator.Split(raw, -1)[0]
	}
	if strings.ContainsAny(raw, " \t") {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if u.Scheme == "" {
		raw = "https://" + raw
		if u, err = url.Parse(raw); err != nil {
			return ""
		}
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || !strings.Contains(u.Hostname(), ".") {
		return ""
	}
	return raw
}

var (
	nonAlnum        = regexp.MustCompile(`[^a-z0-9]+`)
	corporateSuffix = regexp.MustCompile(`(-(inc|llc|ltd|corp|corporation|co|company|lp|llp|plc|l-l-c|incorporated|limited))+$`)
)

// Slug turns a broker name into an id ("Acme Data, Inc." -> "acme-data").
func Slug(name string) string { return slug(name) }

func slug(name string) string {
	s := strings.Trim(nonAlnum.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if trimmed := corporateSuffix.ReplaceAllString(s, ""); trimmed != "" {
		s = trimmed
	}
	return s
}

func uniqueID(base, registryID string, used map[string]bool) string {
	id := base
	if id == "" || used[id] {
		id = strings.Trim(base+"-"+slug(registryID), "-")
	}
	for n := 2; used[id]; n++ {
		id = fmt.Sprintf("%s-%d", base, n)
	}
	used[id] = true
	return id
}
