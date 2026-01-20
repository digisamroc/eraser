package browser

import (
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

// ConfirmationHandler handles clicking confirmation links from emails
type ConfirmationHandler struct {
	client       *http.Client
	brokerDomains map[string]bool
}

// NewConfirmationHandler creates a new handler with known broker domains
func NewConfirmationHandler(brokerDomains []string) *ConfirmationHandler {
	domains := make(map[string]bool)
	for _, d := range brokerDomains {
		// Store both the domain and common variations
		d = strings.ToLower(d)
		domains[d] = true
		// Also allow subdomains
		if !strings.HasPrefix(d, "www.") {
			domains["www."+d] = true
		}
		if !strings.HasPrefix(d, "mail.") {
			domains["mail."+d] = true
		}
		if !strings.HasPrefix(d, "email.") {
			domains["email."+d] = true
		}
	}

	return &ConfirmationHandler{
		client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Allow up to 10 redirects
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		brokerDomains: domains,
	}
}

// ValidateDomain checks if the URL belongs to a known broker domain
func (h *ConfirmationHandler) ValidateDomain(confirmURL string) (bool, string, error) {
	parsed, err := url.Parse(confirmURL)
	if err != nil {
		return false, "", fmt.Errorf("invalid URL: %w", err)
	}

	host := strings.ToLower(parsed.Host)

	// Remove port if present
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// Check exact match
	if h.brokerDomains[host] {
		return true, host, nil
	}

	// Check if it's a subdomain of a known domain
	for domain := range h.brokerDomains {
		if strings.HasSuffix(host, "."+domain) {
			return true, domain, nil
		}
	}

	return false, host, nil
}

// ClickConfirmationLink sends a GET request to the confirmation URL
func (h *ConfirmationHandler) ClickConfirmationLink(confirmURL string, validateDomain bool) (*ConfirmationResult, error) {
	result := &ConfirmationResult{
		URL:          confirmURL,
		RedirectPath: []string{confirmURL},
	}

	// Validate domain if requested
	if validateDomain {
		valid, domain, err := h.ValidateDomain(confirmURL)
		if err != nil {
			result.ErrorMessage = err.Error()
			return result, err
		}
		if !valid {
			result.ErrorMessage = fmt.Sprintf("domain %s is not a known broker domain", domain)
			return result, fmt.Errorf(result.ErrorMessage)
		}
	}

	// Create request with browser-like headers
	req, err := http.NewRequest("GET", confirmURL, nil)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("failed to create request: %v", err)
		return result, err
	}

	// Set headers to look like a real browser
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "keep-alive")

	// Track redirects
	var redirects []string
	h.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("too many redirects")
		}
		redirects = append(redirects, req.URL.String())
		return nil
	}

	// Make the request
	resp, err := h.client.Do(req)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("request failed: %v", err)
		return result, err
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.FinalURL = resp.Request.URL.String()
	result.RedirectPath = append(result.RedirectPath, redirects...)

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
