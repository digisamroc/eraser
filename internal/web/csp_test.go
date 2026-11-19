package web

import (
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// With 'unsafe-inline' in script-src, any HTML injection is script
// execution. All scripts live in /static/js, so the CSP doesn't need it.
func TestCSPForbidsInlineScripts(t *testing.T) {
	_, h := newTestServer(t, testConfig())
	csp := do(h, http.MethodGet, "/settings", nil).Header().Get("Content-Security-Policy")
	var scriptSrc string
	for _, d := range strings.Split(csp, ";") {
		if d = strings.TrimSpace(d); strings.HasPrefix(d, "script-src ") {
			scriptSrc = d
		}
	}
	if scriptSrc != "script-src 'self'" {
		t.Errorf("script-src = %q, want \"script-src 'self'\" (CSP: %s)", scriptSrc, csp)
	}
}

var (
	inlineScript  = regexp.MustCompile(`(?i)<script(\s[^>]*)?>`)
	scriptWithSrc = regexp.MustCompile(`(?i)<script\s[^>]*\bsrc=`)
	inlineHandler = regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
	jsURL         = regexp.MustCompile(`(?i)(href|src|action)\s*=\s*["']?\s*javascript:`)
)

// The CSP would block these, silently breaking the page, so none may exist:
// not in templates (including scripts that build HTML) and not in HTML
// fragments built in Go.
func TestNoInlineScriptsAnywhere(t *testing.T) {
	check := func(name, content string) {
		for _, tag := range inlineScript.FindAllString(content, -1) {
			if !scriptWithSrc.MatchString(tag) {
				t.Errorf("%s: inline <script> block: %s", name, tag)
			}
		}
		for _, loc := range inlineHandler.FindAllStringIndex(content, -1) {
			t.Errorf("%s: inline event handler near %q", name, content[loc[0]:min(loc[1]+30, len(content))])
		}
		if m := jsURL.FindString(content); m != "" {
			t.Errorf("%s: javascript: URL: %s", name, m)
		}
	}

	err := fs.WalkDir(templatesFS, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := templatesFS.ReadFile(path)
		check(path, string(data))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	err = fs.WalkDir(staticFS, "static/js", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasSuffix(path, ".min.js") {
			return err
		}
		data, err := staticFS.ReadFile(path)
		check(path, string(data)) // HTML our scripts build
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	sources, _ := filepath.Glob("*.go")
	for _, src := range sources {
		if strings.HasSuffix(src, "_test.go") {
			continue
		}
		data, err := os.ReadFile(src) //nolint:gosec // G304: this package's own source files
		if err != nil {
			t.Fatal(err)
		}
		check(src, string(data))
	}
}
