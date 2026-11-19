package main

import (
	"bytes"
	"strings"
	"testing"
)

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
