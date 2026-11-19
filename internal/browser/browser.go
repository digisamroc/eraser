// Package browser provides headless Chrome automation for form filling
package browser

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/chromedp/chromedp"

	"github.com/eraser-privacy/eraser/internal/config"
)

// ErrNoSubmitButton means no submit control was found; the form is filled
// but must be submitted by hand.
var ErrNoSubmitButton = errors.New("no submit button found; review and submit the form manually")

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
	Headless      bool
	Timeout       time.Duration
	ScreenshotDir string
	UserAgent     string
	WindowWidth   int
	WindowHeight  int
	WaitForUser   bool         // If true, pause when CAPTCHA detected for user to solve
	WaitCallback  func() error // Called when waiting for user (e.g., to prompt in terminal)
}

// DefaultConfig returns sensible default browser settings
func DefaultConfig() BrowserConfig {
	return BrowserConfig{
		Headless:      true,
		Timeout:       60 * time.Second, // Increased from 30s - many broker sites are slow
		ScreenshotDir: "",
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		WindowWidth:   1920,
		WindowHeight:  1080,
	}
}

// FormResult represents the outcome of a form fill attempt
type FormResult struct {
	Success         bool
	URL             string
	BrokerID        string
	FieldsFilled    []string
	FieldsMissing   []string
	CaptchaFound    bool
	CaptchaType     string
	ScreenshotPath  string
	ErrorMessage    string
	SubmitAttempted bool // a submit control was actually clicked
}

// New starts a browser. The browser lives until Close; per-form timeouts in
// NavigateAndFill only bound that form's actions.
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

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	ctx, cancel := chromedp.NewContext(allocCtx)

	// The first Run on a context starts the browser, which then lives as long
	// as that context. Start it here, on the long-lived context: starting it
	// inside NavigateAndFill's timeout context killed the browser after the
	// first form.
	if _, err := chromedp.Run(ctx, chromedp.Title()); err != nil {
		cancel()
		allocCancel()
		return nil, fmt.Errorf("failed to start browser: %w", err)
	}

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

	// Bound this form's actions; derived from the browser's context.
	ctx, cancel := context.WithTimeout(b.ctx, b.config.Timeout)
	defer cancel()

	if _, err := chromedp.Run(ctx, chromedp.Navigate(url)); err != nil {
		result.ErrorMessage = fmt.Sprintf("navigation failed: %v", err)
		return result, err
	}
	if _, err := chromedp.Run(ctx, chromedp.WaitReady("body")); err != nil {
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

		if b.config.ScreenshotDir != "" {
			screenshotPath, _ := b.takeScreenshot(ctx, brokerID, "captcha_gate")
			result.ScreenshotPath = screenshotPath
		}

		// If WaitForUser is enabled, wait for user to solve the blocking CAPTCHA
		if b.config.WaitForUser && b.config.WaitCallback != nil {
			fmt.Printf("⚠️  Blocking CAPTCHA detected: %s\n", blockingCaptcha.GetCaptchaDescription())
			fmt.Println("   Please solve the CAPTCHA in the browser window...")

			if err := b.config.WaitCallback(); err != nil {
				result.ErrorMessage = fmt.Sprintf("user cancelled: %v", err)
				return result, err
			}

			// User solved CAPTCHA, wait for page to update and then continue to fill form
			time.Sleep(2 * time.Second)
		} else {
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

			if err := b.config.WaitCallback(); err != nil {
				result.ErrorMessage = fmt.Sprintf("user cancelled: %v", err)
				return result, err
			}

			if autoSubmit {
				b.submitAndRecord(ctx, result, brokerID)
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

	result.Success = len(result.FieldsFilled) > 0
	if autoSubmit && result.Success {
		b.submitAndRecord(ctx, result, brokerID)
	}
	return result, nil
}

// submitAndRecord clicks the form's submit control and records the outcome.
func (b *Browser) submitAndRecord(ctx context.Context, result *FormResult, brokerID string) {
	if err := b.submitForm(ctx); err != nil {
		result.ErrorMessage = fmt.Sprintf("submit failed: %v", err)
		return
	}
	result.SubmitAttempted = true
	result.Success = true

	time.Sleep(2 * time.Second)
	if b.config.ScreenshotDir != "" {
		_, _ = b.takeScreenshot(ctx, brokerID, "submitted")
	}
}

// fillFormFields detects and fills form fields with profile data
func (b *Browser) fillFormFields(ctx context.Context) *FillResult {
	filler := NewFormFiller(b.profile)
	return filler.Fill(ctx)
}

// markSubmitJS marks the submit control of a form that contains filled
// fields. Only controls inside such a form count, so a page's unrelated
// buttons ("Delete my account", "Request a demo") are never clicked. A
// <button> without a type submits its form; other buttons need submit-like
// text. Returns false when there is no such control.
const markSubmitJS = `(function() {
	var words = /(submit|send|remove|delete|opt[\s-]?out|request|continue)/i;
	var forms = Array.from(document.forms).filter(function(f) {
		return Array.from(f.elements).some(function(e) {
			return (e.tagName === 'INPUT' || e.tagName === 'TEXTAREA') &&
				!/^(hidden|submit|button|reset|checkbox|radio)$/i.test(e.type) && e.value;
		});
	});
	for (var i = 0; i < forms.length; i++) {
		var controls = forms[i].querySelectorAll('button, input[type="submit"], [role="button"]');
		for (var j = 0; j < controls.length; j++) {
			var el = controls[j];
			if (el.offsetParent === null || el.disabled) continue;
			var type = (el.getAttribute('type') || '').toLowerCase();
			if (type === 'reset') continue;
			var label = (el.innerText || el.value || el.getAttribute('aria-label') || '').trim();
			var isSubmit = type === 'submit' || (el.tagName === 'BUTTON' && !el.hasAttribute('type'));
			if (isSubmit || words.test(label)) {
				el.setAttribute('data-eraser-submit', '1');
				return true;
			}
		}
	}
	return false;
})()`

// submitForm clicks the form's submit control. It never falls back to
// pressing Enter, because that can't confirm anything was submitted.
func (b *Browser) submitForm(ctx context.Context) error {
	found, err := chromedp.Run(ctx, chromedp.Evaluate[bool](markSubmitJS))
	if err != nil {
		return fmt.Errorf("could not search for a submit button: %w", err)
	}
	if !found {
		return ErrNoSubmitButton
	}
	if _, err := chromedp.Run(ctx, chromedp.Click(`[data-eraser-submit="1"]`, chromedp.NodeVisible)); err != nil {
		return fmt.Errorf("could not click the submit button: %w", err)
	}
	return nil
}

// takeScreenshot captures the current page state
func (b *Browser) takeScreenshot(ctx context.Context, brokerID, suffix string) (string, error) {
	buf, err := chromedp.Run(ctx, chromedp.FullScreenshot(90))
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
