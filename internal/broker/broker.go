package broker

import (
	"fmt"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/eraser-privacy/eraser/internal/config"
	"gopkg.in/yaml.v3"
)

func isValidURL(rawURL string) bool {
	if rawURL == "" {
		return true
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	return scheme == "http" || scheme == "https"
}

func sanitizeBroker(b *Broker) {
	if !isValidURL(b.OptOutURL) {
		b.OptOutURL = ""
	}
	if !isValidURL(b.Website) {
		b.Website = ""
	}
}

// TagFormOnly marks a broker that does not process emailed requests; use OptOutURL instead.
const TagFormOnly = "form-only"

var (
	validRegions    = map[string]bool{"us": true, "eu": true, "global": true}
	validCategories = map[string]bool{"people-search": true, "marketing": true, "background-check": true, "data-broker": true}
	idPattern       = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

	// Personal mailbox providers. A broker's legal contact on one of these is
	// unverifiable and may be a private individual, so it is never accepted.
	freemailDomains = map[string]bool{
		"gmail.com": true, "googlemail.com": true, "yahoo.com": true, "ymail.com": true,
		"outlook.com": true, "hotmail.com": true, "live.com": true, "msn.com": true,
		"aol.com": true, "icloud.com": true, "me.com": true, "mac.com": true,
		"proton.me": true, "protonmail.com": true, "gmx.com": true, "gmx.net": true,
		"mail.com": true, "yandex.com": true, "zoho.com": true,
		"comcast.net": true, "att.net": true, "verizon.net": true, "sbcglobal.net": true,
	}
)

type Broker struct {
	ID         string   `yaml:"id"`
	Name       string   `yaml:"name"`
	Email      string   `yaml:"email"`
	Website    string   `yaml:"website,omitempty"`
	OptOutURL  string   `yaml:"opt_out_url,omitempty"`
	Region     string   `yaml:"region"`             // "us", "eu", "global"
	Category   string   `yaml:"category,omitempty"` // "people-search", "marketing", "background-check", "data-broker"
	Notes      string   `yaml:"notes,omitempty"`
	RequiresID bool     `yaml:"requires_id,omitempty"` // If they require ID verification
	Tags       []string `yaml:"tags,omitempty"`
	Source     string   `yaml:"source,omitempty"`      // Where this entry came from, e.g. "ca-cppa" or "manual"
	SourceURL  string   `yaml:"source_url,omitempty"`  // Page that backs up the contact details
	RegistryID string   `yaml:"registry_id,omitempty"` // ID in the source registry
	Disclose   []string `yaml:"disclose,omitempty"`    // extra profile fields this broker needs (config.Disclose* values)
}

// EmailAccepted reports whether the broker processes emailed removal requests.
func (b Broker) EmailAccepted() bool {
	return !slices.Contains(b.Tags, TagFormOnly)
}

// IsFreemailDomain reports whether domain belongs to a personal mailbox provider.
func IsFreemailDomain(domain string) bool {
	return freemailDomains[strings.ToLower(domain)]
}

// ValidateEmail checks that addr is a single bare address on a non-personal domain.
func ValidateEmail(addr string) error {
	if addr == "" {
		return fmt.Errorf("email is required")
	}
	if strings.ContainsAny(addr, "\r\n,;<> ") {
		return fmt.Errorf("email %q must be a single bare address", addr)
	}
	parsed, err := mail.ParseAddress(addr)
	if err != nil || parsed.Address != addr {
		return fmt.Errorf("email %q is not a valid address", addr)
	}
	domain := addr[strings.LastIndex(addr, "@")+1:]
	if IsFreemailDomain(domain) {
		return fmt.Errorf("email %q is a personal mailbox, not a company contact", addr)
	}
	return nil
}

// Validate checks a single broker entry.
func (b Broker) Validate() error {
	if b.ID == "" {
		return fmt.Errorf("id is required")
	}
	if !idPattern.MatchString(b.ID) {
		return fmt.Errorf("id %q must be lowercase letters, digits, and hyphens", b.ID)
	}
	if b.Name == "" {
		return fmt.Errorf("%s: name is required", b.ID)
	}
	if err := ValidateEmail(b.Email); err != nil {
		return fmt.Errorf("%s: %w", b.ID, err)
	}
	if !validRegions[b.Region] {
		return fmt.Errorf("%s: unknown region %q", b.ID, b.Region)
	}
	if b.Category != "" && !validCategories[b.Category] {
		return fmt.Errorf("%s: unknown category %q", b.ID, b.Category)
	}
	if _, err := config.ParseDisclosure(b.Disclose); err != nil {
		return fmt.Errorf("%s: %w", b.ID, err)
	}
	return nil
}

// Validate checks every broker and that IDs are unique.
func (db *BrokerDatabase) Validate() error {
	seen := make(map[string]bool, len(db.Brokers))
	for _, b := range db.Brokers {
		if err := b.Validate(); err != nil {
			return err
		}
		if seen[b.ID] {
			return fmt.Errorf("duplicate id %q", b.ID)
		}
		seen[b.ID] = true
	}
	return nil
}

type BrokerDatabase struct {
	Brokers []Broker `yaml:"brokers"`
}

func LoadFromFile(path string) (*BrokerDatabase, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read broker file: %w", err)
	}

	var db BrokerDatabase
	if err := yaml.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("failed to parse broker file: %w", err)
	}

	for i := range db.Brokers {
		sanitizeBroker(&db.Brokers[i])
	}
	if err := db.Validate(); err != nil {
		return nil, fmt.Errorf("invalid broker file %s: %w", path, err)
	}
	return &db, nil
}

func LoadFromDir(dir string) (*BrokerDatabase, error) {
	db := &BrokerDatabase{}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read broker directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		partialDB, err := LoadFromFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to load %s: %w", entry.Name(), err)
		}

		db.Brokers = append(db.Brokers, partialDB.Brokers...)
	}

	return db, nil
}

func toSet(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, s := range items {
		m[strings.ToLower(s)] = true
	}
	return m
}

// Filter returns the brokers that should receive an emailed request. Global
// brokers are included for any region; form-only brokers are never included.
func (db *BrokerDatabase) Filter(regions []string, excluded []string) []Broker {
	return FilterList(db.Brokers, regions, excluded)
}

// FilterList applies Filter's rules to any list of brokers.
func FilterList(brokers []Broker, regions []string, excluded []string) []Broker {
	regionSet, excludedSet := toSet(regions), toSet(excluded)

	var result []Broker
	for _, b := range brokers {
		if !b.EmailAccepted() {
			continue
		}
		if excludedSet[strings.ToLower(b.ID)] || excludedSet[strings.ToLower(b.Name)] {
			continue
		}
		if len(regionSet) > 0 {
			r := strings.ToLower(b.Region)
			if !regionSet[r] && r != "global" {
				continue
			}
		}
		result = append(result, b)
	}
	return result
}

func (db *BrokerDatabase) FindByID(id string) *Broker {
	id = strings.ToLower(id)
	for i := range db.Brokers {
		if strings.ToLower(db.Brokers[i].ID) == id {
			return &db.Brokers[i]
		}
	}
	return nil
}

func (db *BrokerDatabase) Save(path string) error {
	data, err := yaml.Marshal(db)
	if err != nil {
		return fmt.Errorf("failed to serialize brokers: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

func (db *BrokerDatabase) Add(broker Broker) error {
	if db.FindByID(broker.ID) != nil {
		return fmt.Errorf("broker with ID %q already exists", broker.ID)
	}
	db.Brokers = append(db.Brokers, broker)
	return nil
}

// FindByEmail finds a broker by their email address
func (db *BrokerDatabase) FindByEmail(email string) *Broker {
	email = strings.ToLower(email)
	for i := range db.Brokers {
		if strings.ToLower(db.Brokers[i].Email) == email {
			return &db.Brokers[i]
		}
	}
	return nil
}

// RemoveByEmail removes a broker by their email address
// Returns the removed broker, or nil if not found
func (db *BrokerDatabase) RemoveByEmail(email string) *Broker {
	email = strings.ToLower(email)
	for i := range db.Brokers {
		if strings.ToLower(db.Brokers[i].Email) == email {
			removed := db.Brokers[i]
			db.Brokers = append(db.Brokers[:i], db.Brokers[i+1:]...)
			return &removed
		}
	}
	return nil
}

// RemoveByID removes a broker by their ID
// Returns the removed broker, or nil if not found
func (db *BrokerDatabase) RemoveByID(id string) *Broker {
	id = strings.ToLower(id)
	for i := range db.Brokers {
		if strings.ToLower(db.Brokers[i].ID) == id {
			removed := db.Brokers[i]
			db.Brokers = append(db.Brokers[:i], db.Brokers[i+1:]...)
			return &removed
		}
	}
	return nil
}

// SaveWithBackup saves the database to file, creating a backup first
func (db *BrokerDatabase) SaveWithBackup(path string) error {
	// Create backup
	if _, err := os.Stat(path); err == nil {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read file for backup: %w", err)
		}
		backupPath := path + ".bak"
		if err := os.WriteFile(backupPath, data, 0644); err != nil {
			return fmt.Errorf("failed to create backup: %w", err)
		}
	}

	return db.Save(path)
}
