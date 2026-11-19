package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

const defaultRateLimitMs = 2000

func checkFilePermissions(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if perm := info.Mode().Perm(); perm&0077 != 0 {
		return fmt.Errorf("config file %s has insecure permissions %04o; should be 0600", path, perm)
	}
	return nil
}

type Config struct {
	Profile  Profile     `yaml:"profile"`
	Email    EmailConfig `yaml:"email"`
	Options  Options     `yaml:"options"`
	Inbox    InboxConfig `yaml:"inbox,omitempty"`
	Pipeline Pipeline    `yaml:"pipeline,omitempty"`
}

// Headless reports whether to run the browser headless; true unless the
// config sets browser_headless: false.
func (p Pipeline) Headless() bool {
	return p.BrowserHeadless == nil || *p.BrowserHeadless
}

// InboxConfig holds IMAP settings for monitoring broker responses
type InboxConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Provider      string `yaml:"provider"`       // "gmail", "outlook", "imap"
	Server        string `yaml:"server"`         // e.g., "imap.gmail.com"
	Port          int    `yaml:"port"`           // e.g., 993
	Email         string `yaml:"email"`          // Email address to monitor
	Password      string `yaml:"password"`       // App password (not main password)
	Folder        string `yaml:"folder"`         // Folder to monitor (default: "INBOX")
	AutoArchive   bool   `yaml:"auto_archive"`   // Automatically move processed emails to archive folder
	ArchiveFolder string `yaml:"archive_folder"` // Folder to archive emails to (default: "Eraser")
	// AuthServID names the server that writes your provider's
	// Authentication-Results header (e.g. "mx.google.com"). Known for Gmail
	// and Outlook; required for any other provider, or no sender is verified.
	AuthServID string `yaml:"authserv_id,omitempty"`
}

// Pipeline holds settings for the automation pipeline
type Pipeline struct {
	AutoConfirm       bool  `yaml:"auto_confirm"`               // Auto-click confirmation links
	AutoFillForms     bool  `yaml:"auto_fill_forms"`            // Enable browser automation for forms
	BrowserHeadless   *bool `yaml:"browser_headless,omitempty"` // Run browser in headless mode (default true)
	BrowserTimeoutSec int   `yaml:"browser_timeout_sec"`        // Browser operation timeout
}

type Profile struct {
	FirstName   string `yaml:"first_name"`
	LastName    string `yaml:"last_name"`
	Email       string `yaml:"email"`
	Address     string `yaml:"address,omitempty"`
	City        string `yaml:"city,omitempty"`
	State       string `yaml:"state,omitempty"`
	ZipCode     string `yaml:"zip_code,omitempty"`
	Country     string `yaml:"country,omitempty"`
	Phone       string `yaml:"phone,omitempty"`
	DateOfBirth string `yaml:"date_of_birth,omitempty"`
}

func (p Profile) FullName() string { return p.FirstName + " " + p.LastName }

type EmailConfig struct {
	Provider string     `yaml:"provider"`
	From     string     `yaml:"from"`
	SMTP     SMTPConfig `yaml:"smtp,omitempty"`
}

type Email = EmailConfig

// SMTP TLS modes. With use_tls and no tls_mode, port 465 means implicit TLS
// and any other port means STARTTLS.
const (
	TLSNone     = "none"
	TLSImplicit = "implicit"
	TLSStartTLS = "starttls"
)

type SMTPConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	UseTLS   bool   `yaml:"use_tls"`
	TLSMode  string `yaml:"tls_mode,omitempty"` // "implicit" or "starttls"; default chosen by port
}

// EffectiveTLSMode resolves use_tls, tls_mode, and port into one mode.
func (c SMTPConfig) EffectiveTLSMode() string {
	switch {
	case !c.UseTLS:
		return TLSNone
	case c.TLSMode != "":
		return c.TLSMode
	case c.Port == 465:
		return TLSImplicit
	default:
		return TLSStartTLS
	}
}

type Options struct {
	Template        string   `yaml:"template"`
	DryRun          bool     `yaml:"dry_run"`
	RateLimitMs     int      `yaml:"rate_limit_ms"`
	Regions         []string `yaml:"regions"`
	ExcludedBrokers []string `yaml:"excluded_brokers,omitempty"`
	Disclose        []string `yaml:"disclose,omitempty"`          // optional profile fields to include in emails
	DailyLimit      int      `yaml:"daily_limit,omitempty"`       // max successful sends per rolling 24h; 0 = default
	ResendAfterDays int      `yaml:"resend_after_days,omitempty"` // skip brokers sent to more recently; 0 = default
}

const (
	// DefaultDailyLimit stays well under Gmail's ~500 messages/day.
	DefaultDailyLimit = 250
	// DefaultResendAfterDays leaves brokers time to respond (CCPA allows 45
	// days) while still allowing a monthly re-run.
	DefaultResendAfterDays = 30
)

// EffectiveDailyLimit returns daily_limit or its default.
func (o Options) EffectiveDailyLimit() int {
	if o.DailyLimit > 0 {
		return o.DailyLimit
	}
	return DefaultDailyLimit
}

// EffectiveResendAfterDays returns resend_after_days or its default.
func (o Options) EffectiveResendAfterDays() int {
	if o.ResendAfterDays > 0 {
		return o.ResendAfterDays
	}
	return DefaultResendAfterDays
}

// DataDir returns Eraser's own folder, ~/.eraser, or "" if there is no home
// directory.
func DataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".eraser")
}

// PrepareDir creates dir (0700) if needed. Eraser's own folder is also
// tightened to 0700 if it already exists, since it holds the config, history
// and screenshots. Any other folder (from --config or --db) is left as is.
func PrepareDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if own := DataDir(); own != "" && filepath.Clean(dir) == own {
		return os.Chmod(dir, 0o700) //nolint:gosec // G302: a directory needs x; 0700 is owner-only
	}
	return nil
}

func DefaultConfigPath() string {
	dir := DataDir()
	if dir == "" {
		return "config.yaml"
	}
	return filepath.Join(dir, "config.yaml")
}

func Load(path string) (*Config, error) {
	if err := checkFilePermissions(path); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: %v\n", err)
	}

	data, err := os.ReadFile(path) //nolint:gosec // G304: the config path is the user's own --config flag
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if cfg.Options.Template == "" {
		cfg.Options.Template = "generic"
	}
	if cfg.Options.RateLimitMs == 0 {
		cfg.Options.RateLimitMs = defaultRateLimitMs
	}

	// Set inbox defaults
	if cfg.Inbox.Folder == "" {
		cfg.Inbox.Folder = "INBOX"
	}
	if cfg.Inbox.ArchiveFolder == "" {
		cfg.Inbox.ArchiveFolder = "Eraser"
	}
	if cfg.Inbox.Provider == "gmail" && cfg.Inbox.Server == "" {
		cfg.Inbox.Server = "imap.gmail.com"
		cfg.Inbox.Port = 993
	}
	if cfg.Inbox.Provider == "outlook" && cfg.Inbox.Server == "" {
		cfg.Inbox.Server = "outlook.office365.com"
		cfg.Inbox.Port = 993
	}

	// Set pipeline defaults
	if cfg.Pipeline.BrowserTimeoutSec == 0 {
		cfg.Pipeline.BrowserTimeoutSec = 30
	}

	return &cfg, nil
}

// Save writes the config to a new owner-only file and renames it over path.
// The old file is never rewritten (it may be readable by others), and a crash
// can't leave a truncated config.
func Save(path string, cfg *Config) error {
	if err := PrepareDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to serialize config: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.yaml") // created 0600
	if err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to write config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to write config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}
	return nil
}

func (c *Config) Validate() error {
	if c.Profile.FirstName == "" || c.Profile.LastName == "" {
		return fmt.Errorf("profile: first_name and last_name are required")
	}
	if c.Profile.Email == "" {
		return fmt.Errorf("profile: email is required")
	}
	if c.Email.Provider == "" {
		return fmt.Errorf("email: provider is required")
	}
	if c.Email.From == "" {
		return fmt.Errorf("email: from address is required")
	}

	if c.Email.Provider != "smtp" {
		return fmt.Errorf("email: unknown provider %q (only smtp is supported)", c.Email.Provider)
	}
	if c.Email.SMTP.Host == "" {
		return fmt.Errorf("email.smtp: host is required")
	}
	if c.Email.SMTP.Port == 0 {
		return fmt.Errorf("email.smtp: port is required")
	}
	switch c.Email.SMTP.TLSMode {
	case "", TLSImplicit, TLSStartTLS:
	default:
		return fmt.Errorf("email.smtp: unknown tls_mode %q (want %q or %q)", c.Email.SMTP.TLSMode, TLSImplicit, TLSStartTLS)
	}
	if _, err := c.Options.Disclosure(); err != nil {
		return err
	}
	if c.Options.DailyLimit < 0 {
		return fmt.Errorf("options: daily_limit must not be negative")
	}
	if c.Options.ResendAfterDays < 0 {
		return fmt.Errorf("options: resend_after_days must not be negative")
	}

	return nil
}

// ValidateInbox validates inbox configuration (only called when inbox monitoring is used)
func (c *Config) ValidateInbox() error {
	if !c.Inbox.Enabled {
		return fmt.Errorf("inbox: monitoring is not enabled in config")
	}
	if c.Inbox.Email == "" {
		return fmt.Errorf("inbox: email address is required")
	}
	if c.Inbox.Password == "" {
		return fmt.Errorf("inbox: password (app password) is required")
	}
	if c.Inbox.Server == "" {
		return fmt.Errorf("inbox: IMAP server is required")
	}
	if c.Inbox.Port == 0 {
		return fmt.Errorf("inbox: IMAP port is required")
	}
	return nil
}
