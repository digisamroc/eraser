package inbox

import (
	"testing"
)

func TestFormRequiredPatterns(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected ResponseType
	}{
		{
			name:     "Blackbaud - submit request at URL",
			body:     "please submit your request at https://www.blackbaud.com/company/Data-Subject-Rights-Request",
			expected: ResponseFormRequired,
		},
		{
			name:     "FamilyTreeNow - use opt-out form",
			body:     "please use our Opt-Out Form, linked below, to submit your request",
			expected: ResponseFormRequired,
		},
		{
			name:     "Civis - complete data subject request form",
			body:     "please complete the Data Subject Request Form, which you can find at",
			expected: ResponseFormRequired,
		},
		{
			name:     "Affinity - does not accept privacy requests via email",
			body:     "does not accept privacy requests via email. You can submit a privacy request via our web form",
			expected: ResponseFormRequired,
		},
		{
			name:     "33Across - visit opt-out page",
			body:     "Please visit our opt-out page located at https://www.33across.com/opt-out",
			expected: ResponseFormRequired,
		},
		{
			name:     "PeopleFinders - right to opt-out",
			body:     "Right to Opt-out: If you wish to opt out of our website, you may do so at this link",
			expected: ResponseFormRequired,
		},
		{
			name:     "01Advertising - click following link",
			body:     "please click on the following link to submit your data deletion request",
			expected: ResponseFormRequired,
		},
		{
			name:     "Mediaocean - dedicated online form",
			body:     "we have established a dedicated online form that helps us verify your identity",
			expected: ResponseFormRequired,
		},
		{
			name:     "Do not process via email",
			body:     "We do not process requests via email alone. Please submit via our web form.",
			expected: ResponseFormRequired,
		},
		{
			name:     "Send to customer service",
			body:     "Dear Customer, Please send your request to Customer Service at custserv@example.com",
			expected: ResponseFormRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &Email{
				Body:    tt.body,
				Subject: "Re: Personal Data Removal Request",
			}
			result := ClassifyResponse(email)
			if result.Type != tt.expected {
				t.Errorf("got %s, want %s", result.Type, tt.expected)
			}
		})
	}
}

func TestPendingPatterns(t *testing.T) {
	tests := []struct {
		name     string
		subject  string
		body     string
		expected ResponseType
	}{
		{
			name:     "BeenVerified - received your request",
			subject:  "Your Request Has Been Received",
			body:     "we have received your request. One of our Privacy Specialists will reach out",
			expected: ResponsePending,
		},
		{
			name:     "6sense - ticket assigned",
			subject:  "Request Received - [#REQ-195698]",
			body:     "ticket has been created. Please reference #REQ-195698",
			expected: ResponsePending,
		},
		{
			name:     "Automatic reply in subject",
			subject:  "Automatic reply: Personal Data Removal Request",
			body:     "Thank you for contacting us.",
			expected: ResponsePending,
		},
		{
			name:     "Out of office",
			subject:  "Out of Office Re: Personal Data Removal Request",
			body:     "I am currently out of the office",
			expected: ResponsePending,
		},
		{
			name:     "Thank you for your inquiry",
			subject:  "Re: Personal Data Removal Request",
			body:     "Thank you for your inquiry. This email confirms that we have received your request.",
			expected: ResponsePending,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &Email{
				Subject: tt.subject,
				Body:    tt.body,
			}
			result := ClassifyResponse(email)
			if result.Type != tt.expected {
				t.Errorf("got %s, want %s", result.Type, tt.expected)
			}
		})
	}
}

func TestConfirmationPatterns(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected ResponseType
	}{
		{
			name:     "Click here to confirm",
			body:     "Please click here to confirm your request",
			expected: ResponseConfirmationRequired,
		},
		{
			name:     "Click below to verify",
			body:     "Click below to verify your email address",
			expected: ResponseConfirmationRequired,
		},
		{
			name:     "Please confirm your email",
			body:     "Please confirm your email address to process your request",
			expected: ResponseConfirmationRequired,
		},
		{
			name:     "Verification link",
			body:     "We have sent you a verification link. Please click it to continue.",
			expected: ResponseConfirmationRequired,
		},
		{
			name:     "Click to confirm",
			body:     "Click to confirm your data removal request",
			expected: ResponseConfirmationRequired,
		},
		{
			name:     "Please verify your identity",
			body:     "For security purposes, please verify your identity by clicking the link below",
			expected: ResponseConfirmationRequired,
		},
		{
			name:     "Confirm your request",
			body:     "Click the link to confirm your request: https://example.com/confirm/abc123",
			expected: ResponseConfirmationRequired,
		},
		{
			name:     "Verify SSN last 4",
			body:     "Can you please verify last 4 of your social? We have several individuals with your name.",
			expected: ResponseConfirmationRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &Email{
				Body:    tt.body,
				Subject: "Re: Personal Data Removal Request",
			}
			result := ClassifyResponse(email)
			if result.Type != tt.expected {
				t.Errorf("got %s, want %s", result.Type, tt.expected)
			}
		})
	}
}

func TestRejectionPatterns(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected ResponseType
	}{
		{
			name:     "ACUTRAQ - no record",
			body:     "we do not have any record of a report in our system. ACUTRAQ maintains no files on this person.",
			expected: ResponseRejected,
		},
		{
			name:     "Atlantic Fox - no longer a data broker",
			body:     "Atlantic Fox is no longer registered as an active data broker in any jurisdictions",
			expected: ResponseRejected,
		},
		{
			name:     "Checkr - email no longer in use",
			body:     "The privacy@checkr.com email list is no longer in use",
			expected: ResponseRejected,
		},
		{
			name:     "No data linked to email",
			body:     "We have no data linked to your email in our system.",
			expected: ResponseRejected,
		},
		{
			name:     "B2B platform",
			body:     "Tyler - we are a b2b platform and do not have your information.",
			expected: ResponseRejected,
		},
		{
			name:     "Never existed in database",
			body:     "the information below has never existed in our database.",
			expected: ResponseRejected,
		},
		{
			name:     "FCRA exempt",
			body:     "consumer reporting agencies are exempt as Fair Credit Reporting Act related data so we do not remove data by request.",
			expected: ResponseRejected,
		},
		{
			name:     "Not identified in database",
			body:     "Your email was not identified in our database. This means that we don't have any personal information.",
			expected: ResponseRejected,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &Email{
				Body:    tt.body,
				Subject: "Re: Personal Data Removal Request",
			}
			result := ClassifyResponse(email)
			if result.Type != tt.expected {
				t.Errorf("got %s, want %s", result.Type, tt.expected)
			}
		})
	}
}

func TestSubjectBasedPendingPatterns(t *testing.T) {
	tests := []struct {
		name     string
		subject  string
		body     string
		expected ResponseType
	}{
		{
			name:     "Your Request Has Been Received",
			subject:  "Your Request Has Been Received",
			body:     "",
			expected: ResponsePending,
		},
		{
			name:     "Thank you for your Privacy Request",
			subject:  "Thank you for your Privacy Request",
			body:     "",
			expected: ResponsePending,
		},
		{
			name:     "Ticket number in subject - REQ format",
			subject:  "Request Received - [#REQ-195698] Personal Data Removal Request",
			body:     "",
			expected: ResponsePending,
		},
		{
			name:     "Ticket number in subject - LD format",
			subject:  "#LD00019726 Personal Data Removal Request Legal Request Received",
			body:     "",
			expected: ResponsePending,
		},
		{
			name:     "Support Request with number",
			subject:  "Your Convex Support Request #317855",
			body:     "",
			expected: ResponsePending,
		},
		{
			name:     "Auto-reply with minimal body",
			subject:  "Automatic reply: Personal Data Removal Request",
			body:     "Thank you.",
			expected: ResponsePending,
		},
		{
			name:     "Auto response variant",
			subject:  "Auto-Response: Personal Data Removal Request",
			body:     "",
			expected: ResponsePending,
		},
		{
			name:     "Out of office with minimal body",
			subject:  "Out of Office Re: Personal Data Removal Request",
			body:     "",
			expected: ResponsePending,
		},
		{
			name:     "I have left the company",
			subject:  "I have now left Captify Re: Personal Data Removal Request",
			body:     "",
			expected: ResponsePending,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &Email{
				Subject: tt.subject,
				Body:    tt.body,
			}
			result := ClassifyResponse(email)
			if result.Type != tt.expected {
				t.Errorf("got %s, want %s (confidence: %.2f)", result.Type, tt.expected, result.Confidence)
			}
		})
	}
}

func TestSubjectBasedRejectionPatterns(t *testing.T) {
	tests := []struct {
		name     string
		subject  string
		body     string
		expected ResponseType
	}{
		{
			name:     "Not Found in subject",
			subject:  "[Convex] Re: Deletion Request Update - Not Found",
			body:     "",
			expected: ResponseRejected,
		},
		{
			name:     "No record in subject",
			subject:  "Re: Personal Data Removal Request - No Record Found",
			body:     "",
			expected: ResponseRejected,
		},
		{
			name:     "Unable to locate",
			subject:  "Unable to locate your data - Personal Data Removal Request",
			body:     "",
			expected: ResponseRejected,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &Email{
				Subject: tt.subject,
				Body:    tt.body,
			}
			result := ClassifyResponse(email)
			if result.Type != tt.expected {
				t.Errorf("got %s, want %s (confidence: %.2f)", result.Type, tt.expected, result.Confidence)
			}
		})
	}
}

func TestTestEmailPatterns(t *testing.T) {
	tests := []struct {
		name     string
		subject  string
		body     string
		expected ResponseType
	}{
		{
			name:     "Eraser Test Email in subject",
			subject:  "Eraser Test Email",
			body:     "",
			expected: ResponseSuccess,
		},
		{
			name:     "Test email in body",
			subject:  "Re: Test",
			body:     "This is a test email from Eraser to verify your email configuration.",
			expected: ResponseSuccess,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &Email{
				Subject: tt.subject,
				Body:    tt.body,
			}
			result := ClassifyResponse(email)
			if result.Type != tt.expected {
				t.Errorf("got %s, want %s (confidence: %.2f)", result.Type, tt.expected, result.Confidence)
			}
			if result.NeedsReview {
				t.Errorf("test email should not need review")
			}
		})
	}
}

func TestTicketPatterns(t *testing.T) {
	tests := []struct {
		name     string
		subject  string
		body     string
		expected ResponseType
	}{
		{
			name:     "Ticket #: format",
			subject:  "Ticket #: 259135 Re: Personal Data Removal Request",
			body:     "",
			expected: ResponsePending,
		},
		{
			name:     "Thank you for email to privacy team",
			subject:  "Thank you for your email to Nielsen's Privacy Team Re: Personal Data Removal Request",
			body:     "",
			expected: ResponsePending,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := &Email{
				Subject: tt.subject,
				Body:    tt.body,
			}
			result := ClassifyResponse(email)
			if result.Type != tt.expected {
				t.Errorf("got %s, want %s (confidence: %.2f)", result.Type, tt.expected, result.Confidence)
			}
		})
	}
}
