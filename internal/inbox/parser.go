package inbox

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// ExtractedURLs contains categorized URLs from an email
type ExtractedURLs struct {
	FormURLs         []string // URLs that look like opt-out forms
	ConfirmationURLs []string // URLs that look like confirmation links
	UnsubscribeURLs  []string // Unsubscribe links
	AllURLs          []string // All URLs found
}

// URL patterns for different types of links
var (
	// Strong patterns that clearly indicate an opt-out form (+10 score)
	strongFormPatterns = []string{
		"opt-out", "optout", "opt_out",
		"do-not-sell", "donotsell", "do_not_sell",
		"removal-request", "removal-form", "removalrequest",
		"remove-my-info", "remove-listing", "remove-record",
		"data-request", "dsar", "data-subject",
		"ccpa-request", "gdpr-request",
		"privacy-request", "privacy-form",
		"/optout", "/opt-out", "/removal", "/remove-me",
	}

	// Moderate patterns that may indicate a form (+5 score)
	moderateFormPatterns = []string{
		"suppress", "suppression",
		"ccpa", "gdpr",
		"/remove", "/delete",
	}

	// Weak patterns - only count if no negatives present (+2 score)
	weakFormPatterns = []string{
		"remove", "removal",
		"delete", "deletion",
		"unsubscribe",
	}

	// Patterns that EXCLUDE a URL from being a form (-20 score, disqualifying)
	notFormPatterns = []string{
		// Policy/legal pages (not forms)
		"privacy-policy", "privacy_policy", "privacypolicy",
		"terms-of-service", "terms_of_service", "termsofservice",
		"terms-and-conditions", "terms_and_conditions",
		"cookie-policy", "cookie_policy", "cookiepolicy",
		"/tos", "/terms", "/legal", "/policy",

		// Info/help pages
		"/about", "/contact", "/help", "/faq", "/support",
		"/how-to", "/howto", "/learn", "/info",

		// Auth pages
		"/login", "/signin", "/register", "/signup", "/auth",

		// Account/settings (not removal forms)
		"/account", "/settings", "/preferences", "/profile",
		"/unsubscribe-preferences", "/email-preferences",
		"/manage-preferences", "/communication-preferences",

		// Marketing pages
		"/marketing", "/newsletter", "/subscribe",

		// Documents
		".pdf", ".doc", ".docx",

		// Social media
		"facebook.com", "twitter.com", "linkedin.com", "instagram.com",

		// Generic external domains (not broker forms)
		"google.com", "bit.ly", "tinyurl.com",
	}

	// Patterns that indicate a confirmation link
	confirmPatterns = []string{
		"confirm", "verification", "verify",
		"activate", "validate",
		"click-here", "clickhere",
		"token=", "code=",
		"approve", "accept",
	}

	// Email tracking/pixel patterns (to exclude)
	trackingPatterns = []string{
		"track", "pixel", "beacon",
		"open.gif", "spacer.gif",
		"1x1", "unsubscribe-tracking",
	}

	// URL regex to find URLs in plain text
	urlRegex = regexp.MustCompile(`https?://[^\s<>"']+`)
)

// ParseEmailURLs extracts and categorizes URLs from an email
func ParseEmailURLs(email *Email) ExtractedURLs {
	result := ExtractedURLs{}

	// Extract URLs from both plain text and HTML body
	var allURLs []string

	// From plain text
	if email.Body != "" {
		allURLs = append(allURLs, extractURLsFromText(email.Body)...)
	}

	// From HTML
	if email.HTMLBody != "" {
		allURLs = append(allURLs, extractURLsFromHTML(email.HTMLBody)...)
	}

	// Deduplicate and categorize
	seen := make(map[string]bool)
	for _, rawURL := range allURLs {
		// Clean and normalize URL
		cleanURL := cleanURL(rawURL)
		if cleanURL == "" || seen[cleanURL] {
			continue
		}
		seen[cleanURL] = true

		// Skip tracking pixels
		if isTrackingURL(cleanURL) {
			continue
		}

		result.AllURLs = append(result.AllURLs, cleanURL)

		// Categorize
		lowerURL := strings.ToLower(cleanURL)

		if isFormURL(lowerURL) {
			result.FormURLs = append(result.FormURLs, cleanURL)
		}

		if isConfirmationURL(lowerURL) {
			result.ConfirmationURLs = append(result.ConfirmationURLs, cleanURL)
		}

		if strings.Contains(lowerURL, "unsubscribe") {
			result.UnsubscribeURLs = append(result.UnsubscribeURLs, cleanURL)
		}
	}

	return result
}

// extractURLsFromText finds URLs in plain text
func extractURLsFromText(text string) []string {
	matches := urlRegex.FindAllString(text, -1)
	return matches
}

// extractURLsFromHTML extracts href values from HTML
func extractURLsFromHTML(html string) []string {
	var urls []string

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		// Fallback to regex
		return extractURLsFromText(html)
	}

	// Find all links
	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		if href, exists := s.Attr("href"); exists {
			urls = append(urls, href)
		}
	})

	// Also check for URLs in plain text within the HTML
	urls = append(urls, extractURLsFromText(doc.Text())...)

	return urls
}

// cleanURL normalizes and validates a URL
func cleanURL(rawURL string) string {
	// Remove trailing punctuation that might have been captured
	rawURL = strings.TrimRight(rawURL, ".,;:!?)")

	// Parse to validate
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	// Must be http or https
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ""
	}

	// Must have a host
	if parsed.Host == "" {
		return ""
	}

	return parsed.String()
}

// scoreFormURL calculates how likely a URL is to be an opt-out form
// Returns a score: higher = more likely to be a form
// Negative score = definitely not a form
func scoreFormURL(lowerURL string) int {
	score := 0

	// Check for exclusion patterns first (disqualifying)
	for _, pattern := range notFormPatterns {
		if strings.Contains(lowerURL, pattern) {
			return -20 // Definitely not a form
		}
	}

	// Strong patterns (+10 each)
	for _, pattern := range strongFormPatterns {
		if strings.Contains(lowerURL, pattern) {
			score += 10
		}
	}

	// Moderate patterns (+5 each)
	for _, pattern := range moderateFormPatterns {
		if strings.Contains(lowerURL, pattern) {
			score += 5
		}
	}

	// Weak patterns (+2 each, but only if we have some positive signal already)
	if score > 0 {
		for _, pattern := range weakFormPatterns {
			if strings.Contains(lowerURL, pattern) {
				score += 2
			}
		}
	}

	return score
}

// isFormURL checks if URL looks like an opt-out form
func isFormURL(lowerURL string) bool {
	return scoreFormURL(lowerURL) > 0
}

// isConfirmationURL checks if URL looks like a confirmation link
func isConfirmationURL(lowerURL string) bool {
	for _, pattern := range confirmPatterns {
		if strings.Contains(lowerURL, pattern) {
			return true
		}
	}
	return false
}

// isTrackingURL checks if URL is likely a tracking pixel
func isTrackingURL(url string) bool {
	lowerURL := strings.ToLower(url)
	for _, pattern := range trackingPatterns {
		if strings.Contains(lowerURL, pattern) {
			return true
		}
	}

	// Check for common image extensions that might be tracking pixels
	if strings.HasSuffix(lowerURL, ".gif") ||
		strings.HasSuffix(lowerURL, ".png") && strings.Contains(lowerURL, "pixel") {
		return true
	}

	return false
}

// Email regex for extracting bounced recipients
var emailRegex = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)

// Patterns that precede the bounced email address in NDRs
var bouncedRecipientPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:the\s+following|these)\s+address(?:es)?\s+(?:had\s+permanent\s+)?(?:fatal\s+)?(?:errors?|failed)[:\s]+([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`),
	regexp.MustCompile(`(?i)delivery\s+to\s+(?:the\s+following\s+)?(?:recipient|address)(?:s)?\s+failed[:\s]+([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`),
	regexp.MustCompile(`(?i)(?:original|final)[\s-]?recipient[:\s]+(?:rfc822;)?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`),
	regexp.MustCompile(`(?i)(?:failed|rejected)\s+recipient[:\s]+([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`),
	regexp.MustCompile(`(?i)undeliverable\s+to[:\s]+([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`),
	regexp.MustCompile(`(?i)message\s+could\s+not\s+be\s+delivered\s+to[:\s]+([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`),
	regexp.MustCompile(`(?i)<([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>.*(?:failed|rejected|undeliverable)`),
	regexp.MustCompile(`(?i)to[:\s]+<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>?\s+.*(?:failed|rejected|not\s+exist)`),
}

// ExtractBouncedRecipient extracts the email address that bounced from an NDR email
func ExtractBouncedRecipient(email *Email) string {
	// Combine all text content
	content := email.Body
	if email.HTMLBody != "" {
		content += " " + stripHTMLSimple(email.HTMLBody)
	}

	// Also check subject (sometimes contains the address)
	content += " " + email.Subject

	// Try specific patterns first (more reliable)
	for _, pattern := range bouncedRecipientPatterns {
		matches := pattern.FindStringSubmatch(content)
		if len(matches) > 1 {
			return strings.TrimSpace(matches[1])
		}
	}

	// Fallback: find all email addresses and exclude known system addresses
	allEmails := emailRegex.FindAllString(content, -1)
	excludePatterns := []string{
		"mailer-daemon", "postmaster", "noreply", "no-reply",
		"@gmail.com", "@yahoo.com", "@outlook.com", "@hotmail.com", // sender's own domain
	}

	for _, addr := range allEmails {
		addrLower := strings.ToLower(addr)
		isSystem := false
		for _, exclude := range excludePatterns {
			if strings.Contains(addrLower, exclude) {
				isSystem = true
				break
			}
		}
		if !isSystem {
			return addr
		}
	}

	return ""
}

// stripHTMLSimple removes HTML tags (simple version for bounce parsing)
func stripHTMLSimple(html string) string {
	re := regexp.MustCompile(`<[^>]+>`)
	return re.ReplaceAllString(html, " ")
}

// ExtractConfirmationToken tries to extract a token from a confirmation URL
func ExtractConfirmationToken(confirmURL string) string {
	parsed, err := url.Parse(confirmURL)
	if err != nil {
		return ""
	}

	// Common token parameter names
	tokenParams := []string{"token", "code", "verify", "confirmation", "key", "id"}

	query := parsed.Query()
	for _, param := range tokenParams {
		if val := query.Get(param); val != "" {
			return val
		}
	}

	// Check if token might be in the path
	parts := strings.Split(parsed.Path, "/")
	for i, part := range parts {
		if part == "confirm" || part == "verify" {
			if i+1 < len(parts) && len(parts[i+1]) > 10 {
				return parts[i+1]
			}
		}
	}

	return ""
}

// GetPrimaryFormURL returns the most likely opt-out form URL using scoring
func GetPrimaryFormURL(urls ExtractedURLs, brokerDomain string) string {
	if len(urls.FormURLs) == 0 {
		return ""
	}

	type scoredURL struct {
		url   string
		score int
	}

	var scored []scoredURL

	for _, u := range urls.FormURLs {
		lowerURL := strings.ToLower(u)
		score := scoreFormURL(lowerURL)

		// Skip negative scores (disqualified)
		if score < 0 {
			continue
		}

		// Bonus for matching broker domain (+20)
		if brokerDomain != "" && strings.Contains(lowerURL, strings.ToLower(brokerDomain)) {
			score += 20
		}

		scored = append(scored, scoredURL{url: u, score: score})
	}

	// Return the highest-scored URL
	if len(scored) == 0 {
		return ""
	}

	best := scored[0]
	for _, s := range scored[1:] {
		if s.score > best.score {
			best = s
		}
	}

	return best.url
}

// GetPrimaryConfirmationURL returns the most likely confirmation URL
func GetPrimaryConfirmationURL(urls ExtractedURLs, brokerDomain string) string {
	// Prefer URLs that match the broker domain
	for _, u := range urls.ConfirmationURLs {
		if strings.Contains(strings.ToLower(u), brokerDomain) {
			return u
		}
	}

	// Return first confirmation URL if any
	if len(urls.ConfirmationURLs) > 0 {
		return urls.ConfirmationURLs[0]
	}

	return ""
}
