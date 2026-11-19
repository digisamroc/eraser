package browser

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ConfirmationResult holds the outcome of clicking a confirmation link
type ConfirmationResult struct {
	Success      bool
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

	// Check for success indicators
	result.Success = h.isSuccessResponse(resp.StatusCode, result.ResponseBody)

	if !result.Success && result.ErrorMessage == "" {
		result.ErrorMessage = fmt.Sprintf("confirmation may have failed (status %d)", resp.StatusCode)
	}

	return result, nil
}

// isSuccessResponse checks if the response indicates successful confirmation
func (h *ConfirmationHandler) isSuccessResponse(statusCode int, body string) bool {
	// Check HTTP status
	if statusCode < 200 || statusCode >= 400 {
		return false
	}

	bodyLower := strings.ToLower(body)

	// Success indicators
	successPatterns := []string{
		"successfully",
		"confirmed",
		"verification complete",
		"verified",
		"opt-out complete",
		"removal complete",
		"request received",
		"request confirmed",
		"thank you",
		"has been removed",
		"been deleted",
		"been processed",
		"unsubscribed",
		"opted out",
	}

	for _, pattern := range successPatterns {
		if strings.Contains(bodyLower, pattern) {
			return true
		}
	}

	// Failure indicators (if these are present, it's NOT a success)
	failurePatterns := []string{
		"link expired",
		"link invalid",
		"already confirmed",
		"error occurred",
		"something went wrong",
		"could not",
		"unable to",
		"failed",
	}

	for _, pattern := range failurePatterns {
		if strings.Contains(bodyLower, pattern) {
			return false
		}
	}

	// If status is 200 and no failure patterns, assume success
	return statusCode == 200
}

// ExtractConfirmationStatus extracts a human-readable status from the response
func (h *ConfirmationHandler) ExtractConfirmationStatus(result *ConfirmationResult) string {
	if result.Success {
		return "Confirmation successful"
	}

	bodyLower := strings.ToLower(result.ResponseBody)

	if strings.Contains(bodyLower, "expired") {
		return "Link expired"
	}
	if strings.Contains(bodyLower, "already") {
		return "Already confirmed/processed"
	}
	if strings.Contains(bodyLower, "invalid") {
		return "Invalid link"
	}
	if result.StatusCode == 404 {
		return "Link not found (404)"
	}
	if result.StatusCode >= 500 {
		return "Server error"
	}

	return "Unknown status"
}
