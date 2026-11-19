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
		Email:   EmailConfig{Provider: "smtp", From: "j@example.com", SMTP: SMTPConfig{Host: "h", Port: 465}},
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
