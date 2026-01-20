package inbox

import (
	"regexp"
	"strings"
)

// ResponseType represents the type of broker response
type ResponseType string

const (
	ResponseFormRequired         ResponseType = "form_required"         // Need to fill out a form
	ResponseConfirmationRequired ResponseType = "confirmation_required" // Need to click confirmation link
	ResponseSuccess              ResponseType = "success"               // Removal confirmed/completed
	ResponseRejected             ResponseType = "rejected"              // Request denied
	ResponsePending              ResponseType = "pending"               // Processing, will follow up
	ResponseBounced              ResponseType = "bounced"               // Email bounced - invalid address
	ResponseUnknown              ResponseType = "unknown"               // Needs manual review
)

// ClassifiedResponse represents a classified email response
type ClassifiedResponse struct {
	Email            *Email
	Type             ResponseType
	URLs             ExtractedURLs
	FormURL          string // Primary form URL (if form_required)
	ConfirmURL       string // Primary confirmation URL (if confirmation_required)
	BouncedRecipient string // Email address that bounced (if bounced)
	Confidence       float64
	Reason           string // Human-readable reason for classification
	NeedsReview      bool   // Whether manual review is recommended
}

// Keyword patterns for classification
var (
	// Success indicators
	successPatterns = []regexp.Regexp{
		*regexp.MustCompile(`(?i)request\s+(has\s+been\s+)?(completed|processed|fulfilled)`),
		*regexp.MustCompile(`(?i)successfully\s+(removed|deleted|opted\s*out)`),
		*regexp.MustCompile(`(?i)your\s+(data|information)\s+(has\s+been\s+)?(removed|deleted)`),
		*regexp.MustCompile(`(?i)opt[\s-]?out\s+(request\s+)?(is\s+)?(complete|confirmed)`),
		*regexp.MustCompile(`(?i)we\s+have\s+(removed|deleted)`),
		*regexp.MustCompile(`(?i)no\s+longer\s+(have|hold|store)\s+your\s+(data|information)`),
	}

	// Form required indicators
	formRequiredPatterns = []regexp.Regexp{
		*regexp.MustCompile(`(?i)please\s+(complete|fill\s*(out|in)?|submit)\s+(the|our|this)?\s*(form|request)`),
		*regexp.MustCompile(`(?i)visit\s+(the\s+)?(following\s+)?(link|url|page)\s+to\s+(complete|submit|verify)`),
		*regexp.MustCompile(`(?i)click\s+(here|below|the\s+link)\s+to\s+(begin|start|submit|complete)`),
		*regexp.MustCompile(`(?i)(must|need\s+to)\s+(verify|confirm)\s+your\s+(identity|request)`),
		*regexp.MustCompile(`(?i)submit\s+a\s+(formal\s+)?request\s+(through|via|at)`),
		*regexp.MustCompile(`(?i)use\s+(our|the)\s+(online|web)\s*(form|portal|tool)`),
		// Redirect to form patterns (from real broker emails)
		*regexp.MustCompile(`(?i)please\s+submit\s+(your\s+)?request\s+(at|via|through)\s+`),
		*regexp.MustCompile(`(?i)please\s+use\s+(our|the)\s+(opt[\s-]?out|removal|privacy)\s*(form|page|link)`),
		*regexp.MustCompile(`(?i)complete\s+(the|our|a)\s+(data\s+subject|privacy|opt[\s-]?out)\s*(access\s+)?(request\s+)?form`),
		*regexp.MustCompile(`(?i)submit\s+(a\s+|your\s+)?(request|form)\s+(via|through|at|using)\s+(our\s+)?(online|web|interactive)`),
		*regexp.MustCompile(`(?i)(does\s+not|do\s+not|cannot)\s+accept\s+privacy\s+requests?\s+(via|by|through)\s+email`),
		*regexp.MustCompile(`(?i)this\s+email\s+(address\s+)?is\s+not\s+intended\s+for\s+privacy`),
		*regexp.MustCompile(`(?i)visit\s+(our|the)\s+(opt[\s-]?out|removal|privacy)\s*(page|form|portal)`),
		*regexp.MustCompile(`(?i)(data\s+subject|privacy)\s+requests?\s+(can|should|must)\s+be\s+(filed|submitted)\s+(at|via)`),
		*regexp.MustCompile(`(?i)go\s+to\s+(the\s+)?(link|url|page)\s+(below|above)`),
		*regexp.MustCompile(`(?i)please\s+click\s+(on\s+)?(the\s+)?following\s+link`),
		*regexp.MustCompile(`(?i)you\s+(can|may)\s+submit\s+.{0,30}(privacy|opt[\s-]?out)`),
		*regexp.MustCompile(`(?i)right\s+to\s+(opt[\s-]?out|delete|know)[:\s]`),
		// Additional form patterns from real emails
		*regexp.MustCompile(`(?i)we\s+(have\s+)?established\s+a\s+dedicated\s+(online\s+)?form`),
		*regexp.MustCompile(`(?i)we\s+do\s+not\s+process\s+requests?\s+via\s+email`),
		*regexp.MustCompile(`(?i)please\s+send\s+(your?\s+)?request\s+to\s+customer\s+service`),
		*regexp.MustCompile(`(?i)is\s+not\s+(a\s+)?mechanism\s+for.{0,30}(privacy|request)`),
		*regexp.MustCompile(`(?i)please\s+complete\s+your\s+(request|form)`),
	}

	// Confirmation required indicators (need to click a link to verify identity/email)
	confirmationPatterns = []regexp.Regexp{
		*regexp.MustCompile(`(?i)click\s+(here|below|the\s+link)\s+to\s+(confirm|verify|validate)`),
		*regexp.MustCompile(`(?i)please\s+(confirm|verify)\s+(your\s+)?(email|request|identity)`),
		*regexp.MustCompile(`(?i)verification\s+(link|email|code)`),
		*regexp.MustCompile(`(?i)confirm\s+your\s+(email\s+)?(address)?`),
		*regexp.MustCompile(`(?i)click\s+(to\s+)?confirm`),
		// Verification of identity patterns
		*regexp.MustCompile(`(?i)(can|could)\s+you\s+(please\s+)?verify`),
		*regexp.MustCompile(`(?i)verify\s+(your\s+)?(last\s+4|ssn|social)`),
	}

	// Rejection indicators
	rejectionPatterns = []regexp.Regexp{
		*regexp.MustCompile(`(?i)(cannot|can't|unable\s+to)\s+(process|complete|fulfill)\s+(your\s+)?request`),
		*regexp.MustCompile(`(?i)request\s+(has\s+been\s+)?(denied|rejected|declined)`),
		*regexp.MustCompile(`(?i)do\s+not\s+have\s+(any\s+)?(data|information|records)\s+(about|for|on)\s+you`),
		*regexp.MustCompile(`(?i)not\s+found\s+in\s+our\s+(system|database|records)`),
		*regexp.MustCompile(`(?i)no\s+(matching\s+)?(records?|data|information)\s+found`),
		*regexp.MustCompile(`(?i)exempt\s+from\s+(CCPA|GDPR|this\s+request)`),
		// No data found patterns (from real broker emails)
		*regexp.MustCompile(`(?i)(do\s+not|don't)\s+have\s+(any\s+)?record`),
		*regexp.MustCompile(`(?i)no\s+(matching\s+)?record\s+(of\s+)?(a\s+)?report`),
		*regexp.MustCompile(`(?i)maintains?\s+no\s+(files?|records?|data)`),
		// Service discontinued patterns
		*regexp.MustCompile(`(?i)no\s+longer\s+(registered|operating)\s+(as\s+)?(an?\s+)?(active\s+)?data\s+broker`),
		*regexp.MustCompile(`(?i)(this\s+)?(email|inbox)(\s+\w+)?\s+(is\s+)?(no\s+longer|being\s+retired)`),
		*regexp.MustCompile(`(?i)service\s+offerings?\s+no\s+longer\s+include`),
		// Additional rejection patterns from real emails
		*regexp.MustCompile(`(?i)(we\s+)?(have\s+)?no\s+data\s+(linked|associated|related)\s+to\s+(your|this)`),
		*regexp.MustCompile(`(?i)not\s+identified\s+in\s+our\s+database`),
		*regexp.MustCompile(`(?i)(we\s+are|we're)\s+a\s+b2b\s+(platform|company|business)`),
		*regexp.MustCompile(`(?i)has\s+never\s+existed\s+in\s+our\s+database`),
		*regexp.MustCompile(`(?i)consumer\s+reporting\s+agenc(y|ies)\s+(is|are)\s+exempt`),
		*regexp.MustCompile(`(?i)fair\s+credit\s+reporting\s+act.{0,30}exempt`),
		*regexp.MustCompile(`(?i)we\s+do\s+not\s+(remove|delete)\s+data\s+by\s+request`),
		*regexp.MustCompile(`(?i)(your\s+)?(email|name|address|information)\s+was\s+not\s+identified`),
		// Wrong email address patterns
		*regexp.MustCompile(`(?i)(this\s+)?(email|inbox)\s+(address\s+)?(is\s+)?not\s+(a\s+)?(mechanism|intended)\s+(for|to)`),
		*regexp.MustCompile(`(?i)not\s+intended\s+for\s+(the\s+)?(submission|handling)\s+of\s+privacy`),
		*regexp.MustCompile(`(?i)will\s+not\s+be\s+considered\s+a\s+valid\s+submission`),
	}

	// Pending indicators
	pendingPatterns = []regexp.Regexp{
		*regexp.MustCompile(`(?i)(is\s+being|currently\s+being)\s+(processed|reviewed|handled)`),
		*regexp.MustCompile(`(?i)will\s+(process|complete|handle)\s+(your\s+)?request\s+within`),
		*regexp.MustCompile(`(?i)please\s+allow\s+(\d+)\s+(days|business\s+days|weeks)`),
		*regexp.MustCompile(`(?i)we('ll|\s+will)\s+(get\s+back|respond|follow\s+up)`),
		*regexp.MustCompile(`(?i)request\s+(has\s+been\s+)?(received|acknowledged)`),
		// Request acknowledgment patterns (from real broker emails)
		*regexp.MustCompile(`(?i)thank\s+you\s+for\s+(your\s+)?(inquiry|email|contacting|reaching|privacy)`),
		*regexp.MustCompile(`(?i)we\s+(have\s+)?received\s+your\s+(request|email|inquiry)`),
		*regexp.MustCompile(`(?i)(has\s+been\s+)?assigned\s+(a\s+)?(ticket|case|reference)\s*(number|#|id)?`),
		*regexp.MustCompile(`(?i)one\s+of\s+our\s+.{0,30}(will\s+)?(reach\s+out|respond|contact)`),
		*regexp.MustCompile(`(?i)ticket\s+(has\s+been\s+)?(created|opened|received)`),
		// Additional patterns for better subject line matching
		*regexp.MustCompile(`(?i)your\s+request\s+has\s+been\s+received`),
		*regexp.MustCompile(`(?i)support\s+request\s*#?\d+`),
		*regexp.MustCompile(`(?i)legal\s+request\s+received`),
		*regexp.MustCompile(`(?i)i\s+(have\s+)?(now\s+)?left\s+`), // Person left the company
		*regexp.MustCompile(`(?i)no\s+longer\s+with\s+(the\s+)?(company|organization)`),
		// Additional pending patterns from real emails
		*regexp.MustCompile(`(?i)(will\s+be\s+)?(removed|deleted)\s+from\s+our\s+database.{0,20}\d+\s+days`),
		*regexp.MustCompile(`(?i)once\s+verified.{0,30}(will\s+be\s+)?(processed|complete)`),
		*regexp.MustCompile(`(?i)this\s+(message\s+)?confirms\s+(our\s+)?receipt`),
		*regexp.MustCompile(`(?i)we\s+appreciate\s+your\s+interest\s+in\s+exercising`),
		*regexp.MustCompile(`(?i)request\s+(will\s+be\s+)?(processed|fulfilled)`),
		*regexp.MustCompile(`(?i)automatic\s+reply`),
		*regexp.MustCompile(`(?i)auto[\s-]?response`),
	}

	// Subject-specific pending patterns (stronger signal when in subject)
	subjectPendingPatterns = []regexp.Regexp{
		*regexp.MustCompile(`(?i)^automatic\s+reply`),
		*regexp.MustCompile(`(?i)^auto[\s-]?reply`),
		*regexp.MustCompile(`(?i)^auto[\s-]?response`),
		*regexp.MustCompile(`(?i)^out\s+of\s+office`),
		*regexp.MustCompile(`(?i)request\s+received`),
		*regexp.MustCompile(`(?i)has\s+been\s+received`),
		*regexp.MustCompile(`(?i)thank\s+you\s+for\s+your\s+(privacy|data|removal|email)`),
		*regexp.MustCompile(`(?i)thank\s+you\s+for\s+(your\s+)?email\s+to`), // "Thank you for your email to Nielsen's Privacy Team"
		*regexp.MustCompile(`(?i)thanks\s+for\s+(reaching|contacting)`),
		*regexp.MustCompile(`(?i)#[A-Z]{0,3}[-]?\d{5,}`), // Ticket numbers like #REQ-195698, #LD00019726
		*regexp.MustCompile(`(?i)request\s*#\s*\d+`),
		*regexp.MustCompile(`(?i)support\s+request`),
		*regexp.MustCompile(`(?i)ticket\s*[\(#]\s*:?\s*\d+`), // Ticket (259135) or Ticket #259135 or Ticket #: 259135
		*regexp.MustCompile(`(?i)we\s+have\s+received\s+your\s+ticket`),
		*regexp.MustCompile(`(?i)i\s+(have\s+)?(now\s+)?left\s+`), // Person left the company
		*regexp.MustCompile(`(?i)no\s+longer\s+with\s+(the\s+)?(company|organization)`),
		*regexp.MustCompile(`(?i)office\s+closed`),
		*regexp.MustCompile(`(?i)response\s+to\s+your\s+email`),
	}

	// Test email patterns (should be skipped from review)
	testEmailPatterns = []regexp.Regexp{
		*regexp.MustCompile(`(?i)eraser\s+test\s+email`),
		*regexp.MustCompile(`(?i)test\s+email\s+from\s+eraser`),
		*regexp.MustCompile(`(?i)this\s+is\s+a\s+test\s+email`),
	}

	// Subject-specific rejection patterns
	subjectRejectionPatterns = []regexp.Regexp{
		*regexp.MustCompile(`(?i)not\s+found`),
		*regexp.MustCompile(`(?i)no\s+record`),
		*regexp.MustCompile(`(?i)unable\s+to\s+(locate|find|process)`),
		*regexp.MustCompile(`(?i)request\s+(denied|rejected)`),
	}

	// Subject-specific success patterns
	subjectSuccessPatterns = []regexp.Regexp{
		*regexp.MustCompile(`(?i)opt[\s-]?out\s+(has\s+been\s+)?completed`),
		*regexp.MustCompile(`(?i)(has\s+been\s+|successfully\s+)?(removed|deleted)`),
		*regexp.MustCompile(`(?i)ticket.+solved`),
		*regexp.MustCompile(`(?i)request\s+(has\s+been\s+)?(completed|processed|fulfilled)`),
	}

	// Subject-specific form required patterns
	subjectFormPatterns = []regexp.Regexp{
		*regexp.MustCompile(`(?i)opt[\s-]?out\s+instructions`),
		*regexp.MustCompile(`(?i)removal\s+instructions`),
		*regexp.MustCompile(`(?i)how\s+to\s+(opt[\s-]?out|remove)`),
	}

	// Bounce/undeliverable indicators
	bouncePatterns = []regexp.Regexp{
		*regexp.MustCompile(`(?i)delivery\s+(to\s+.+\s+)?(has\s+)?failed`),
		*regexp.MustCompile(`(?i)undeliverable`),
		*regexp.MustCompile(`(?i)delivery\s+status\s+notification`),
		*regexp.MustCompile(`(?i)returned\s+mail`),
		*regexp.MustCompile(`(?i)mail\s+delivery\s+failed`),
		*regexp.MustCompile(`(?i)message\s+(could\s+)?not\s+(be\s+)?delivered`),
		*regexp.MustCompile(`(?i)could\s+not\s+be\s+delivered`),
		*regexp.MustCompile(`(?i)delivery\s+failure`),
		*regexp.MustCompile(`(?i)permanent\s+(failure|error)`),
		*regexp.MustCompile(`(?i)address\s+rejected`),
		*regexp.MustCompile(`(?i)user\s+unknown`),
		*regexp.MustCompile(`(?i)mailbox\s+not\s+found`),
		*regexp.MustCompile(`(?i)no\s+such\s+user`),
		*regexp.MustCompile(`(?i)(mailbox|recipient|address)\s+(does\s+not|doesn't)\s+exist`),
		*regexp.MustCompile(`(?i)invalid\s+(recipient|address|mailbox)`),
		*regexp.MustCompile(`(?i)unknown\s+(recipient|user|address)`),
		*regexp.MustCompile(`(?i)550\s+.*\s+(rejected|unknown|not\s+found)`),
		*regexp.MustCompile(`(?i)554\s+.*\s+(rejected|failed)`),
	}

	// Senders that indicate a bounce email
	bounceSenders = []string{
		"mailer-daemon",
		"postmaster",
		"mail delivery system",
		"mail delivery subsystem",
		"mailerdaemon",
		"noreply",
		"no-reply",
		"mailsystem",
	}
)

// ClassifyResponse analyzes an email and determines the response type
func ClassifyResponse(email *Email) ClassifiedResponse {
	result := ClassifiedResponse{
		Email:      email,
		Type:       ResponseUnknown,
		Confidence: 0.0,
	}

	// Extract URLs from the email
	result.URLs = ParseEmailURLs(email)

	// Get the text content to analyze
	content := email.Body
	if content == "" {
		content = stripHTML(email.HTMLBody)
	}
	content = strings.ToLower(content)

	// Also check subject
	subject := strings.ToLower(email.Subject)

	// Check if this is a test email (from Eraser itself)
	if isTestEmail(subject, content) {
		result.Type = ResponseSuccess
		result.Confidence = 1.0
		result.Reason = "Test email from Eraser - email configuration verified"
		result.NeedsReview = false
		return result
	}

	// Check if this is a bounce email FIRST (before other classification)
	if isBounceEmail(email, subject, content) {
		result.Type = ResponseBounced
		result.Confidence = 0.95
		result.Reason = "Email delivery failed - address may be invalid"
		result.BouncedRecipient = ExtractBouncedRecipient(email)
		result.NeedsReview = false // Bounces are clear-cut
		return result
	}

	// Score each category
	scores := map[ResponseType]int{
		ResponseSuccess:              0,
		ResponseFormRequired:         0,
		ResponseConfirmationRequired: 0,
		ResponseRejected:             0,
		ResponsePending:              0,
	}

	// Check for subject-specific patterns (strong signal - worth +3)
	for _, pattern := range subjectPendingPatterns {
		if pattern.MatchString(subject) {
			scores[ResponsePending] += 3
		}
	}
	for _, pattern := range subjectRejectionPatterns {
		if pattern.MatchString(subject) {
			scores[ResponseRejected] += 3
		}
	}
	for _, pattern := range subjectSuccessPatterns {
		if pattern.MatchString(subject) {
			scores[ResponseSuccess] += 3
		}
	}
	for _, pattern := range subjectFormPatterns {
		if pattern.MatchString(subject) {
			scores[ResponseFormRequired] += 3
		}
	}

	// Check success patterns
	for _, pattern := range successPatterns {
		if pattern.MatchString(content) || pattern.MatchString(subject) {
			scores[ResponseSuccess]++
		}
	}

	// Check form required patterns
	for _, pattern := range formRequiredPatterns {
		if pattern.MatchString(content) {
			scores[ResponseFormRequired]++
		}
	}

	// Check confirmation patterns
	for _, pattern := range confirmationPatterns {
		if pattern.MatchString(content) {
			scores[ResponseConfirmationRequired]++
		}
	}

	// Check rejection patterns
	for _, pattern := range rejectionPatterns {
		if pattern.MatchString(content) || pattern.MatchString(subject) {
			scores[ResponseRejected]++
		}
	}

	// Check pending patterns
	for _, pattern := range pendingPatterns {
		if pattern.MatchString(content) {
			scores[ResponsePending]++
		}
	}

	// Boost scores based on URL presence
	if len(result.URLs.FormURLs) > 0 {
		scores[ResponseFormRequired] += 2
	}
	if len(result.URLs.ConfirmationURLs) > 0 {
		scores[ResponseConfirmationRequired] += 2
	}

	// Find the highest scoring type and second highest
	maxScore := 0
	secondScore := 0
	for responseType, score := range scores {
		if score > maxScore {
			secondScore = maxScore
			maxScore = score
			result.Type = responseType
		} else if score > secondScore {
			secondScore = score
		}
	}

	// Calculate confidence based on margin over second best
	// If maxScore is significantly higher than secondScore, confidence is higher
	if maxScore > 0 {
		if secondScore == 0 {
			// Only one type matched - high confidence
			result.Confidence = 0.85
		} else {
			// Multiple types matched - confidence based on margin
			margin := float64(maxScore-secondScore) / float64(maxScore)
			result.Confidence = 0.5 + (margin * 0.4) // Range: 0.5 to 0.9
		}
		// Boost confidence for strong subject matches (score >= 3 from subject patterns)
		if maxScore >= 3 {
			result.Confidence = max(result.Confidence, 0.75)
		}
		// High confidence when classification is backed by concrete URLs
		if result.Type == ResponseFormRequired && len(result.URLs.FormURLs) > 0 {
			result.Confidence = max(result.Confidence, 0.85)
		}
		if result.Type == ResponseConfirmationRequired && len(result.URLs.ConfirmationURLs) > 0 {
			result.Confidence = max(result.Confidence, 0.85)
		}
	}

	// If no patterns matched, try to infer from URLs
	if maxScore == 0 {
		if len(result.URLs.ConfirmationURLs) > 0 {
			result.Type = ResponseConfirmationRequired
			result.Confidence = 0.5
		} else if len(result.URLs.FormURLs) > 0 {
			result.Type = ResponseFormRequired
			result.Confidence = 0.5
		}
	}

	// Set primary URLs
	brokerDomain := email.FromDomain
	result.FormURL = GetPrimaryFormURL(result.URLs, brokerDomain)
	result.ConfirmURL = GetPrimaryConfirmationURL(result.URLs, brokerDomain)

	// Set reason based on classification
	result.Reason = getClassificationReason(result.Type, maxScore)

	// Flag for manual review only if unknown or very low confidence
	// Classified items with any confidence don't need review since patterns matched
	result.NeedsReview = result.Type == ResponseUnknown || (result.Confidence < 0.4 && result.Type != ResponseUnknown)

	return result
}

// getClassificationReason returns a human-readable reason
func getClassificationReason(responseType ResponseType, score int) string {
	switch responseType {
	case ResponseSuccess:
		return "Email indicates removal request was completed successfully"
	case ResponseFormRequired:
		return "Email contains link to opt-out form that needs to be filled"
	case ResponseConfirmationRequired:
		return "Email contains confirmation link that needs to be clicked"
	case ResponseRejected:
		return "Broker rejected or could not process the removal request"
	case ResponsePending:
		return "Request is being processed, follow-up may be needed"
	case ResponseUnknown:
		return "Could not automatically classify this response"
	default:
		return "Unknown classification"
	}
}

// stripHTML removes HTML tags from content (simple version)
func stripHTML(html string) string {
	// Remove script and style elements (Go regex doesn't support backreferences)
	reScript := regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	html = reScript.ReplaceAllString(html, "")
	reStyle := regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	html = reStyle.ReplaceAllString(html, "")

	// Remove HTML tags
	reTags := regexp.MustCompile(`<[^>]+>`)
	html = reTags.ReplaceAllString(html, " ")

	// Decode common HTML entities
	html = strings.ReplaceAll(html, "&nbsp;", " ")
	html = strings.ReplaceAll(html, "&amp;", "&")
	html = strings.ReplaceAll(html, "&lt;", "<")
	html = strings.ReplaceAll(html, "&gt;", ">")
	html = strings.ReplaceAll(html, "&quot;", "\"")

	// Collapse whitespace
	reWhitespace := regexp.MustCompile(`\s+`)
	html = reWhitespace.ReplaceAllString(html, " ")

	return strings.TrimSpace(html)
}

// ClassifyBatch classifies multiple emails
func ClassifyBatch(emails []Email) []ClassifiedResponse {
	results := make([]ClassifiedResponse, len(emails))
	for i, email := range emails {
		results[i] = ClassifyResponse(&email)
	}
	return results
}

// ClassifyBySubjectOnly classifies based on subject line only (for reclassifying database records)
// Returns the response type, confidence, and whether it needs review
func ClassifyBySubjectOnly(subject string) (ResponseType, float64, bool) {
	subject = strings.ToLower(subject)

	// Score each category based on subject patterns
	scores := map[ResponseType]int{
		ResponseSuccess:              0,
		ResponseFormRequired:         0,
		ResponseConfirmationRequired: 0,
		ResponseRejected:             0,
		ResponsePending:              0,
	}

	// Check subject-specific patterns (strong signal - worth +3)
	for _, pattern := range subjectPendingPatterns {
		if pattern.MatchString(subject) {
			scores[ResponsePending] += 3
		}
	}
	for _, pattern := range subjectRejectionPatterns {
		if pattern.MatchString(subject) {
			scores[ResponseRejected] += 3
		}
	}
	for _, pattern := range subjectSuccessPatterns {
		if pattern.MatchString(subject) {
			scores[ResponseSuccess] += 3
		}
	}
	for _, pattern := range subjectFormPatterns {
		if pattern.MatchString(subject) {
			scores[ResponseFormRequired] += 3
		}
	}

	// Also check regular patterns against subject
	for _, pattern := range successPatterns {
		if pattern.MatchString(subject) {
			scores[ResponseSuccess]++
		}
	}
	for _, pattern := range rejectionPatterns {
		if pattern.MatchString(subject) {
			scores[ResponseRejected]++
		}
	}
	for _, pattern := range pendingPatterns {
		if pattern.MatchString(subject) {
			scores[ResponsePending]++
		}
	}

	// Find highest scoring type
	maxScore := 0
	bestType := ResponseUnknown
	for responseType, score := range scores {
		if score > maxScore {
			maxScore = score
			bestType = responseType
		}
	}

	// Calculate confidence (lower for subject-only)
	var confidence float64
	needsReview := true

	if maxScore >= 3 {
		confidence = 0.7 // Strong subject match
		needsReview = false
	} else if maxScore >= 1 {
		confidence = 0.4 // Weak match
		needsReview = true
	} else {
		bestType = ResponseUnknown
		confidence = 0.0
		needsReview = true
	}

	return bestType, confidence, needsReview
}

// FilterByType filters classified responses by type
func FilterByType(responses []ClassifiedResponse, responseType ResponseType) []ClassifiedResponse {
	var filtered []ClassifiedResponse
	for _, r := range responses {
		if r.Type == responseType {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// GetActionableResponses returns responses that need action
func GetActionableResponses(responses []ClassifiedResponse) []ClassifiedResponse {
	var actionable []ClassifiedResponse
	for _, r := range responses {
		if r.Type == ResponseFormRequired || r.Type == ResponseConfirmationRequired {
			actionable = append(actionable, r)
		}
	}
	return actionable
}

// Summary provides a summary of classified responses
type Summary struct {
	Total           int
	Success         int
	FormRequired    int
	ConfirmRequired int
	Rejected        int
	Pending         int
	Bounced         int
	Unknown         int
	NeedReview      int
}

// SummarizeResponses generates a summary of classified responses
func SummarizeResponses(responses []ClassifiedResponse) Summary {
	summary := Summary{Total: len(responses)}

	for _, r := range responses {
		switch r.Type {
		case ResponseSuccess:
			summary.Success++
		case ResponseFormRequired:
			summary.FormRequired++
		case ResponseConfirmationRequired:
			summary.ConfirmRequired++
		case ResponseRejected:
			summary.Rejected++
		case ResponsePending:
			summary.Pending++
		case ResponseBounced:
			summary.Bounced++
		case ResponseUnknown:
			summary.Unknown++
		}
		if r.NeedsReview {
			summary.NeedReview++
		}
	}

	return summary
}

// isTestEmail checks if an email is a test email from Eraser
func isTestEmail(subject, content string) bool {
	for _, pattern := range testEmailPatterns {
		if pattern.MatchString(subject) || pattern.MatchString(content) {
			return true
		}
	}
	return false
}

// isBounceEmail checks if an email is a bounce/undeliverable notification
func isBounceEmail(email *Email, subject, content string) bool {
	// Check if sender looks like a mail system
	fromLower := strings.ToLower(email.From)
	fromNameLower := strings.ToLower(email.FromName)

	isBounceSource := false
	for _, sender := range bounceSenders {
		if strings.Contains(fromLower, sender) || strings.Contains(fromNameLower, sender) {
			isBounceSource = true
			break
		}
	}

	// Check subject and content for bounce patterns
	bounceScore := 0
	for _, pattern := range bouncePatterns {
		if pattern.MatchString(subject) {
			bounceScore += 2 // Subject match is strong signal
		}
		if pattern.MatchString(content) {
			bounceScore++
		}
	}

	// Email is considered a bounce if:
	// - It's from a mail system sender AND has bounce patterns, OR
	// - It has strong bounce patterns (score >= 3)
	return (isBounceSource && bounceScore > 0) || bounceScore >= 3
}

// GetBouncedResponses returns responses that are bounced emails
func GetBouncedResponses(responses []ClassifiedResponse) []ClassifiedResponse {
	return FilterByType(responses, ResponseBounced)
}
