// Package browser provides headless Chrome automation for form filling
package browser

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/eraser-privacy/eraser/internal/config"
)

// Browser wraps chromedp for headless Chrome automation
type Browser struct {
	allocCtx    context.Context
	allocCancel context.CancelFunc
	ctx         context.Context
	cancel      context.CancelFunc
	config      BrowserConfig
	profile     *config.Profile
}

// BrowserConfig holds browser automation settings
type BrowserConfig struct {
	Headless       bool
	Timeout        time.Duration
	ScreenshotDir  string
	UserAgent      string
	WindowWidth    int
	WindowHeight   int
	WaitForUser    bool          // If true, pause when CAPTCHA detected for user to solve
	WaitCallback   func() error  // Called when waiting for user (e.g., to prompt in terminal)
}

// DefaultConfig returns sensible default browser settings
func DefaultConfig() BrowserConfig {
	return BrowserConfig{
		Headless:       true,
		Timeout:        60 * time.Second, // Increased from 30s - many broker sites are slow
		ScreenshotDir:  "",
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		WindowWidth:    1920,
		WindowHeight:   1080,
	}
}

// FormResult represents the outcome of a form fill attempt
type FormResult struct {
	Success        bool
	URL            string
	BrokerID       string
	FieldsFilled   []string
	FieldsMissing  []string
	CaptchaFound   bool
	CaptchaType    string
	ScreenshotPath string
	ErrorMessage   string
	SubmitAttempted bool
}

// New creates a new Browser instance
func New(cfg BrowserConfig, profile *config.Profile) (*Browser, error) {
	opts := []chromedp.ExecAllocatorOption{
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.DisableGPU,
		chromedp.UserAgent(cfg.UserAgent),
		chromedp.WindowSize(cfg.WindowWidth, cfg.WindowHeight),
	}

	if cfg.Headless {
		opts = append(opts, chromedp.Headless)
	}

	// Create allocator context
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)

	// Create browser context
	ctx, cancel := chromedp.NewContext(allocCtx)

	return &Browser{
		allocCtx:    allocCtx,
		allocCancel: allocCancel,
		ctx:         ctx,
		cancel:      cancel,
		config:      cfg,
		profile:     profile,
	}, nil
}

// Close cleans up browser resources
func (b *Browser) Close() {
	if b.cancel != nil {
		b.cancel()
	}
	if b.allocCancel != nil {
		b.allocCancel()
	}
}

// NavigateAndFill navigates to a URL and attempts to fill any opt-out form
func (b *Browser) NavigateAndFill(url string, brokerID string, autoSubmit bool) (*FormResult, error) {
	result := &FormResult{
		URL:      url,
		BrokerID: brokerID,
	}

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(b.ctx, b.config.Timeout)
	defer cancel()

	// Navigate to the URL
	err := chromedp.Run(ctx, chromedp.Navigate(url))
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("navigation failed: %v", err)
		return result, err
	}

	// Wait for page to load
	err = chromedp.Run(ctx, chromedp.WaitReady("body"))
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("page load failed: %v", err)
		return result, err
	}

	// Small delay for dynamic content
	time.Sleep(2 * time.Second)

	// PHASE 1: Check for blocking CAPTCHA (e.g., Cloudflare challenge, CAPTCHA gate before form)
	// Some sites like TruePeopleSearch show CAPTCHA before the actual form is visible
	blockingCaptcha := b.detectCaptcha(ctx)
	if blockingCaptcha.Found && blockingCaptcha.IsCaptchaBlocking() {
		result.CaptchaFound = true
		result.CaptchaType = blockingCaptcha.Type

		// Take screenshot of CAPTCHA gate
		if b.config.ScreenshotDir != "" {
			screenshotPath, _ := b.takeScreenshot(ctx, brokerID, "captcha_gate")
			result.ScreenshotPath = screenshotPath
		}

		// If WaitForUser is enabled, wait for user to solve the blocking CAPTCHA
		if b.config.WaitForUser && b.config.WaitCallback != nil {
			fmt.Printf("⚠️  Blocking CAPTCHA detected: %s\n", blockingCaptcha.GetCaptchaDescription())
			fmt.Println("   Please solve the CAPTCHA in the browser window...")

			// Call the callback (e.g., prompt user in terminal)
			if err := b.config.WaitCallback(); err != nil {
				result.ErrorMessage = fmt.Sprintf("user cancelled: %v", err)
				return result, err
			}

			// User solved CAPTCHA, wait for page to update and then continue to fill form
			time.Sleep(2 * time.Second)
			// Continue to PHASE 2 below (fill form)
		} else {
			// No WaitForUser - return with CAPTCHA detected
			result.ErrorMessage = fmt.Sprintf("Blocking CAPTCHA detected: %s - use --wait flag to solve manually", blockingCaptcha.Type)
			return result, nil
		}
	}

	// PHASE 2: Fill form fields (either no blocking CAPTCHA, or user already solved it)
	fillResult := b.fillFormFields(ctx)
	result.FieldsFilled = fillResult.FilledFields
	result.FieldsMissing = fillResult.MissingFields

	// Small delay after filling for any dynamic updates
	time.Sleep(1 * time.Second)

	// PHASE 3: Check for form-level CAPTCHA (e.g., reCAPTCHA on the form itself)
	formCaptcha := b.detectCaptcha(ctx)
	if formCaptcha.Found && formCaptcha.IsCaptchaBlocking() {
		result.CaptchaFound = true
		result.CaptchaType = formCaptcha.Type

		// Take screenshot showing filled form + CAPTCHA for human review
		if b.config.ScreenshotDir != "" {
			screenshotPath, _ := b.takeScreenshot(ctx, brokerID, "filled_captcha")
			result.ScreenshotPath = screenshotPath
		}

		// If WaitForUser is enabled, pause for user to solve CAPTCHA
		if b.config.WaitForUser && b.config.WaitCallback != nil {
			fmt.Printf("⚠️  Form CAPTCHA detected: %s\n", formCaptcha.GetCaptchaDescription())
			fmt.Println("   Form has been pre-filled. Please solve the CAPTCHA...")

			// Call the callback (e.g., prompt user in terminal)
			if err := b.config.WaitCallback(); err != nil {
				result.ErrorMessage = fmt.Sprintf("user cancelled: %v", err)
				return result, err
			}

			// User solved CAPTCHA, now submit the form
			if autoSubmit {
				err = b.submitForm(ctx)
				if err != nil {
					result.ErrorMessage = fmt.Sprintf("submit failed after CAPTCHA: %v", err)
				} else {
					result.SubmitAttempted = true
					result.Success = true

					// Take screenshot of result
					time.Sleep(2 * time.Second)
					if b.config.ScreenshotDir != "" {
						b.takeScreenshot(ctx, brokerID, "submitted")
					}
				}
			}
			return result, nil
		}

		// Form is filled, user just needs to solve CAPTCHA and submit
		result.ErrorMessage = fmt.Sprintf("CAPTCHA detected: %s - form filled, solve CAPTCHA and submit", formCaptcha.Type)
		return result, nil
	}

	// Take screenshot after filling (no CAPTCHA case)
	if b.config.ScreenshotDir != "" {
		screenshotPath, _ := b.takeScreenshot(ctx, brokerID, "filled")
		result.ScreenshotPath = screenshotPath
	}

	// Submit form if requested and no CAPTCHA
	if autoSubmit && !result.CaptchaFound && len(result.FieldsFilled) > 0 {
		err = b.submitForm(ctx)
		if err != nil {
			result.ErrorMessage = fmt.Sprintf("submit failed: %v", err)
		} else {
			result.SubmitAttempted = true
			result.Success = true

			// Take screenshot of result
			time.Sleep(2 * time.Second)
			if b.config.ScreenshotDir != "" {
				b.takeScreenshot(ctx, brokerID, "submitted")
			}
		}
	} else if len(result.FieldsFilled) > 0 {
		result.Success = true
	}

	return result, nil
}

// fillFormFields detects and fills form fields with profile data
func (b *Browser) fillFormFields(ctx context.Context) *FillResult {
	filler := NewFormFiller(b.profile)
	return filler.Fill(ctx)
}

// submitForm attempts to submit the form
func (b *Browser) submitForm(ctx context.Context) error {
	// Try common submit button selectors
	submitSelectors := []string{
		"button[type='submit']",
		"input[type='submit']",
		"button:contains('Submit')",
		"button:contains('Remove')",
		"button:contains('Opt Out')",
		"button:contains('Delete')",
		"button:contains('Request')",
		".submit-button",
		"#submit",
		"#submit-btn",
	}

	for _, selector := range submitSelectors {
		var exists bool
		err := chromedp.Run(ctx, chromedp.Evaluate(
			fmt.Sprintf(`document.querySelector("%s") !== null`, selector),
			&exists,
		))
		if err == nil && exists {
			err = chromedp.Run(ctx, chromedp.Click(selector, chromedp.NodeVisible))
			if err == nil {
				return nil
			}
		}
	}

	// Try pressing Enter on the last input field
	err := chromedp.Run(ctx,
		chromedp.KeyEvent("\r"),
	)
	if err != nil {
		return fmt.Errorf("could not find or click submit button")
	}

	return nil
}

// takeScreenshot captures the current page state
func (b *Browser) takeScreenshot(ctx context.Context, brokerID, suffix string) (string, error) {
	var buf []byte
	err := chromedp.Run(ctx, chromedp.FullScreenshot(&buf, 90))
	if err != nil {
		return "", err
	}

	// Create screenshot directory if needed
	if err := os.MkdirAll(b.config.ScreenshotDir, 0755); err != nil {
		return "", err
	}

	filename := fmt.Sprintf("%s_%s_%d.png", brokerID, suffix, time.Now().Unix())
	filepath := filepath.Join(b.config.ScreenshotDir, filename)

	if err := os.WriteFile(filepath, buf, 0644); err != nil {
		return "", err
	}

	return filename, nil
}

// GetPageHTML returns the current page HTML
func (b *Browser) GetPageHTML(ctx context.Context) (string, error) {
	var html string
	err := chromedp.Run(ctx, chromedp.OuterHTML("html", &html))
	return html, err
}

// GetPageTitle returns the current page title
func (b *Browser) GetPageTitle(ctx context.Context) (string, error) {
	var title string
	err := chromedp.Run(ctx, chromedp.Title(&title))
	return title, err
}

// WaitForNavigation waits for page navigation to complete
func (b *Browser) WaitForNavigation(ctx context.Context) error {
	return chromedp.Run(ctx, chromedp.WaitReady("body"))
}

// EnablePageEvents enables page lifecycle event monitoring
func (b *Browser) EnablePageEvents(ctx context.Context) error {
	return chromedp.Run(ctx, page.Enable())
}
