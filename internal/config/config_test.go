package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSendLimitDefaults(t *testing.T) {
	var o Options
	if got := o.EffectiveDailyLimit(); got != DefaultDailyLimit {
		t.Errorf("EffectiveDailyLimit() = %d, want %d", got, DefaultDailyLimit)
	}
	if got := o.EffectiveResendAfterDays(); got != DefaultResendAfterDays {
		t.Errorf("EffectiveResendAfterDays() = %d, want %d", got, DefaultResendAfterDays)
	}
	o = Options{DailyLimit: 100, ResendAfterDays: 45}
	if o.EffectiveDailyLimit() != 100 || o.EffectiveResendAfterDays() != 45 {
		t.Errorf("explicit values not honored: %+v", o)
	}
}

func TestValidateRejectsNegativeLimits(t *testing.T) {
	base := Config{
		Profile: Profile{FirstName: "J", LastName: "D", Email: "j@example.com"},
		Email:   EmailConfig{Provider: "smtp", From: "j@example.com", SMTP: SMTPConfig{Host: "h", Port: 465, UseTLS: true}},
	}
	for name, o := range map[string]Options{
		"daily_limit":       {DailyLimit: -1},
		"resend_after_days": {ResendAfterDays: -1},
	} {
		cfg := base
		cfg.Options = o
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: expected error for negative value", name)
		}
	}
}

func TestSaveTightensExistingFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("profile: {}\n"), 0o644); err != nil { //nolint:gosec // deliberately too open; Save must tighten it

		t.Fatal(err)
	}
	if err := Save(path, &Config{}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("permissions = %04o, want 0600", perm)
	}
}

func TestPipelineHeadless(t *testing.T) {
	dir := t.TempDir()
	for yaml, want := range map[string]bool{
		"profile: {}\n":                         true,
		"pipeline: {browser_headless: false}\n": false,
		"pipeline: {browser_headless: true}\n":  true,
	} {
		path := filepath.Join(dir, "c.yaml")
		if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := cfg.Pipeline.Headless(); got != want {
			t.Errorf("%q: Headless() = %v, want %v", yaml, got, want)
		}
	}
}

// Save must never write personal data into the existing file (which may be
// readable by others until it is tightened, or truncated by a crash): it
// writes a new 0600 file and renames it into place. A hard link to the old
// file shows whether the old file was rewritten.
func TestSaveReplacesFileInsteadOfRewritingIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX hard links and permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("profile: {}\n"), 0o644); err != nil { //nolint:gosec // deliberately too open
		t.Fatal(err)
	}
	link := filepath.Join(dir, "old-link.yaml")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}

	if err := Save(path, &Config{Profile: Profile{FirstName: "Jane"}}); err != nil {
		t.Fatal(err)
	}
	if old, _ := os.ReadFile(link); string(old) != "profile: {}\n" { //nolint:gosec // test file
		t.Errorf("Save rewrote the existing file in place; old file now holds %q", old)
	}
	cfg, err := Load(path)
	if err != nil || cfg.Profile.FirstName != "Jane" {
		t.Fatalf("Load after Save = %+v, %v", cfg, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Errorf("leftover files after Save: %v", entries)
	}
}

func TestSaveTightensEraserDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".eraser")
	if err := os.Mkdir(dir, 0o755); err != nil { //nolint:gosec // deliberately too open
		t.Fatal(err)
	}
	if err := Save(DefaultConfigPath(), &Config{}); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(dir); info.Mode().Perm() != 0o700 {
		t.Errorf("~/.eraser permissions = %04o, want 0700", info.Mode().Perm())
	}
}

// A --config path elsewhere is the user's choice; its folder isn't changed.
func TestSaveLeavesOtherDirsAlone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	dir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(dir, 0o755); err != nil { //nolint:gosec // a normal shared folder
		t.Fatal(err)
	}
	if err := Save(filepath.Join(dir, "config.yaml"), &Config{}); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(dir); info.Mode().Perm() != 0o755 {
		t.Errorf("folder permissions changed to %04o", info.Mode().Perm())
	}
}

func TestValidateRejectsPlaintextSMTPToRemoteHost(t *testing.T) {
	for host, wantErr := range map[string]bool{
		"smtp.example.com": true,
		"10.0.0.5":         true,
		"localhost":        false,
		"127.0.0.1":        false,
		"::1":              false,
	} {
		cfg := Config{
			Profile: Profile{FirstName: "J", LastName: "D", Email: "j@example.com"},
			Email:   EmailConfig{Provider: "smtp", From: "j@example.com", SMTP: SMTPConfig{Host: host, Port: 25}},
		}
		if err := cfg.Validate(); (err != nil) != wantErr {
			t.Errorf("%s: Validate() = %v, want error %v", host, err, wantErr)
		}
	}
}

// pipeline.auto_confirm and auto_fill_forms were never read and are gone;
// configs that still have them must keep loading.
func TestLoadIgnoresRemovedPipelineKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte("pipeline: {auto_confirm: true, auto_fill_forms: true, browser_timeout_sec: 45}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Pipeline.BrowserTimeoutSec != 45 {
		t.Errorf("browser_timeout_sec = %d", cfg.Pipeline.BrowserTimeoutSec)
	}
}
