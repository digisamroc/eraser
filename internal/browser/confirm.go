package browser

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// ConfirmOutcome is what a confirmation page says happened.
type ConfirmOutcome int

const (
	// ConfirmUnknown: the page doesn't clearly say either way (no signal, or
	// mixed signals). The broker's status must not change.
	ConfirmUnknown ConfirmOutcome = iota
	ConfirmConfirmed
	ConfirmFailed
)

func (o ConfirmOutcome) String() string {
	switch o {
	case ConfirmConfirmed:
		return "confirmed"
	case ConfirmFailed:
		return "failed"
	}
	return "unknown"
}

// ConfirmationResult holds the outcome of clicking a confirmation link
type ConfirmationResult struct {
	Outcome      ConfirmOutcome
	URL          string
	FinalURL     string
	StatusCode   int
	ResponseBody string
	ErrorMessage string
	RedirectPath []string
}

// ConfirmationHandler handles clicking confirmation links from emails.
// Which URLs it may follow is decided per call (see ClickConfirmationLink).
type ConfirmationHandler struct {
	client *http.Client
}

// NewConfirmationHandler creates a new handler.
func NewConfirmationHandler() *ConfirmationHandler {
	return &ConfirmationHandler{client: &http.Client{Timeout: 30 * time.Second}}
}

// ErrDisallowedURL means a confirmation URL, or a redirect it led to, is not
// one the caller allowed.
var ErrDisallowedURL = errors.New("URL is not on an allowed broker domain")

// ClickConfirmationLink sends a GET request to confirmURL. allowed must
// approve the URL and every redirect hop; the request stops before any hop
// it rejects, so a broker link can't bounce the click to another site.
func (h *ConfirmationHandler) ClickConfirmationLink(confirmURL string, allowed func(*url.URL) bool) (*ConfirmationResult, error) {
	result := &ConfirmationResult{
		URL:          confirmURL,
		RedirectPath: []string{confirmURL},
	}

	req, err := http.NewRequest("GET", confirmURL, nil)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("failed to create request: %v", err)
		return result, err
	}
	if !allowed(req.URL) {
		result.ErrorMessage = fmt.Sprintf("%s: %s", ErrDisallowedURL, req.URL.Host)
		return result, fmt.Errorf("%w: %s", ErrDisallowedURL, req.URL.Host)
	}

	// Set headers to look like a real browser
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	// A client per call: the redirect check closes over this call's state.
	client := &http.Client{
		Timeout: h.client.Timeout,
		CheckRedirect: func(next *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			if !allowed(next.URL) {
				return fmt.Errorf("%w: redirect to %s", ErrDisallowedURL, next.URL.Host)
			}
			result.RedirectPath = append(result.RedirectPath, next.URL.String())
			return nil
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("request failed: %v", err)
		return result, err
	}
	defer func() { _ = resp.Body.Close() }()

	result.StatusCode = resp.StatusCode
	result.FinalURL = resp.Request.URL.String()

	// Read response body (limited to 64KB)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("failed to read response: %v", err)
		return result, err
	}
	result.ResponseBody = string(body)

	result.Outcome = classifyConfirmation(resp.StatusCode, result.ResponseBody)
	if result.Outcome == ConfirmFailed {
		result.ErrorMessage = fmt.Sprintf("confirmation failed (status %d)", resp.StatusCode)
	}

	return result, nil
}

// Words a confirmation page uses when it worked, and when it didn't. Failure
// words include negated and "already" forms of the success words, so a page
// saying "not confirmed" or "already confirmed" has mixed signals.
var (
	confirmSuccessWords = []string{
		"successfully", "confirmed", "verification complete", "verified",
		"opt-out complete", "removal complete", "request received",
		"has been removed", "been deleted", "been processed", "unsubscribed",
		"opted out", "thank you for confirming", "thanks for confirming",
	}
	confirmFailureWords = []string{
		"expired", "invalid", "error occurred", "something went wrong",
		"could not", "unable to", "failed", "not confirmed", "not verified",
		"unconfirmed", "unverified", "already",
	}
)

// classifyConfirmation decides what a confirmation page says. A non-2xx
// status failed. Otherwise only the page's visible text counts (not scripts
// or styles): success words alone mean confirmed, failure words alone mean
// failed, and both or neither mean unknown.
func classifyConfirmation(statusCode int, body string) ConfirmOutcome {
	if statusCode < 200 || statusCode >= 300 {
		return ConfirmFailed
	}
	text := visibleText(body)
	has := func(words []string) bool {
		for _, w := range words {
			if strings.Contains(text, w) {
				return true
			}
		}
		return false
	}
	success, failure := has(confirmSuccessWords), has(confirmFailureWords)
	switch {
	case success && !failure:
		return ConfirmConfirmed
	case failure && !success:
		return ConfirmFailed
	}
	return ConfirmUnknown
}

// visibleText returns the lowercased text of an HTML (or plain text) body,
// without the contents of script, style, noscript and template elements.
func visibleText(body string) string {
	var b strings.Builder
	z := html.NewTokenizer(strings.NewReader(body))
	skip := 0
	for {
		switch z.Next() {
		case html.ErrorToken:
			return strings.ToLower(b.String())
		case html.StartTagToken:
			if hiddenElement(z) {
				skip++
			}
		case html.EndTagToken:
			if hiddenElement(z) && skip > 0 {
				skip--
			}
		case html.TextToken:
			if skip == 0 {
				b.Write(z.Text())
				b.WriteByte(' ')
			}
		}
	}
}

func hiddenElement(z *html.Tokenizer) bool {
	name, _ := z.TagName()
	switch string(name) {
	case "script", "style", "noscript", "template":
		return true
	}
	return false
}

// ExtractConfirmationStatus extracts a human-readable status from the response
func (h *ConfirmationHandler) ExtractConfirmationStatus(result *ConfirmationResult) string {
	switch result.Outcome {
	case ConfirmConfirmed:
		return "Confirmation successful"
	case ConfirmUnknown:
		return "The page doesn't say whether it worked; open the link yourself to check"
	}

	text := visibleText(result.ResponseBody)
	if strings.Contains(text, "expired") {
		return "Link expired"
	}
	if strings.Contains(text, "invalid") {
		return "Invalid link"
	}
	if result.StatusCode == 404 {
		return "Link not found (404)"
	}
	if result.StatusCode >= 500 {
		return "Server error"
	}

	return "Confirmation failed"
}
