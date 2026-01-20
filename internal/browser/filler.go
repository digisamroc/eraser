package browser

import (
	"context"
	"fmt"
	"strings"

	"github.com/chromedp/chromedp"

	"github.com/eraser-privacy/eraser/internal/config"
)

// FormFiller handles form field detection and auto-filling
type FormFiller struct {
	profile *config.Profile
}

// FillResult contains the outcome of form filling
type FillResult struct {
	FilledFields  []string
	MissingFields []string
	Errors        []string
}

// FieldMapping maps detected field types to profile values
type FieldMapping struct {
	FieldType    string
	ProfileValue string
	Selectors    []string
	Patterns     []string // Patterns to match in name/id/placeholder
}

// NewFormFiller creates a new FormFiller
func NewFormFiller(profile *config.Profile) *FormFiller {
	return &FormFiller{profile: profile}
}

// Fill detects and fills form fields
func (f *FormFiller) Fill(ctx context.Context) *FillResult {
	result := &FillResult{}

	// Get all field mappings based on profile
	mappings := f.getFieldMappings()

	for _, mapping := range mappings {
		if mapping.ProfileValue == "" {
			result.MissingFields = append(result.MissingFields, mapping.FieldType)
			continue
		}

		filled := f.tryFillField(ctx, mapping)
		if filled {
			result.FilledFields = append(result.FilledFields, mapping.FieldType)
		}
	}

	return result
}

// getFieldMappings returns mappings for all profile fields
func (f *FormFiller) getFieldMappings() []FieldMapping {
	return []FieldMapping{
		{
			FieldType:    "email",
			ProfileValue: f.profile.Email,
			Selectors: []string{
				"input[type='email']",
				"input[name='email']",
				"input[id='email']",
				"input[name*='email']",
				"input[id*='email']",
				"input[placeholder*='email' i]",
				"input[autocomplete='email']",
			},
			Patterns: []string{"email", "e-mail", "e_mail"},
		},
		{
			FieldType:    "firstName",
			ProfileValue: f.profile.FirstName,
			Selectors: []string{
				"input[name='firstName']",
				"input[name='first_name']",
				"input[name='fname']",
				"input[id='firstName']",
				"input[id='first_name']",
				"input[name*='first']",
				"input[id*='first']",
				"input[placeholder*='first name' i]",
				"input[autocomplete='given-name']",
			},
			Patterns: []string{"first", "fname", "given"},
		},
		{
			FieldType:    "lastName",
			ProfileValue: f.profile.LastName,
			Selectors: []string{
				"input[name='lastName']",
				"input[name='last_name']",
				"input[name='lname']",
				"input[id='lastName']",
				"input[id='last_name']",
				"input[name*='last']",
				"input[id*='last']",
				"input[placeholder*='last name' i]",
				"input[autocomplete='family-name']",
			},
			Patterns: []string{"last", "lname", "family", "surname"},
		},
		{
			FieldType:    "fullName",
			ProfileValue: f.profile.FirstName + " " + f.profile.LastName,
			Selectors: []string{
				"input[name='name']",
				"input[name='fullName']",
				"input[name='full_name']",
				"input[id='name']",
				"input[id='fullName']",
				"input[placeholder*='full name' i]",
				"input[placeholder*='your name' i]",
				"input[autocomplete='name']",
			},
			Patterns: []string{"fullname", "full_name", "your_name"},
		},
		{
			FieldType:    "phone",
			ProfileValue: f.profile.Phone,
			Selectors: []string{
				"input[type='tel']",
				"input[name='phone']",
				"input[name='telephone']",
				"input[name='mobile']",
				"input[id='phone']",
				"input[name*='phone']",
				"input[id*='phone']",
				"input[placeholder*='phone' i]",
				"input[autocomplete='tel']",
			},
			Patterns: []string{"phone", "tel", "mobile", "cell"},
		},
		{
			FieldType:    "address",
			ProfileValue: f.profile.Address,
			Selectors: []string{
				"input[name='address']",
				"input[name='street']",
				"input[name='address1']",
				"input[name='streetAddress']",
				"input[id='address']",
				"input[name*='address']",
				"input[name*='street']",
				"input[placeholder*='address' i]",
				"input[placeholder*='street' i]",
				"input[autocomplete='street-address']",
				"input[autocomplete='address-line1']",
			},
			Patterns: []string{"address", "street", "addr"},
		},
		{
			FieldType:    "city",
			ProfileValue: f.profile.City,
			Selectors: []string{
				"input[name='city']",
				"input[id='city']",
				"input[name*='city']",
				"input[placeholder*='city' i]",
				"input[autocomplete='address-level2']",
			},
			Patterns: []string{"city", "town", "locality"},
		},
		{
			FieldType:    "state",
			ProfileValue: f.profile.State,
			Selectors: []string{
				"input[name='state']",
				"input[id='state']",
				"input[name*='state']",
				"input[placeholder*='state' i]",
				"select[name='state']",
				"select[id='state']",
				"input[autocomplete='address-level1']",
			},
			Patterns: []string{"state", "province", "region"},
		},
		{
			FieldType:    "zipCode",
			ProfileValue: f.profile.ZipCode,
			Selectors: []string{
				"input[name='zip']",
				"input[name='zipCode']",
				"input[name='zip_code']",
				"input[name='postalCode']",
				"input[name='postal_code']",
				"input[id='zip']",
				"input[name*='zip']",
				"input[name*='postal']",
				"input[placeholder*='zip' i]",
				"input[placeholder*='postal' i]",
				"input[autocomplete='postal-code']",
			},
			Patterns: []string{"zip", "postal", "postcode"},
		},
		{
			FieldType:    "country",
			ProfileValue: f.profile.Country,
			Selectors: []string{
				"input[name='country']",
				"input[id='country']",
				"select[name='country']",
				"select[id='country']",
				"input[autocomplete='country-name']",
			},
			Patterns: []string{"country", "nation"},
		},
		{
			FieldType:    "dateOfBirth",
			ProfileValue: f.profile.DateOfBirth,
			Selectors: []string{
				"input[name='dob']",
				"input[name='dateOfBirth']",
				"input[name='date_of_birth']",
				"input[name='birthdate']",
				"input[name='birth_date']",
				"input[type='date']",
				"input[id='dob']",
				"input[placeholder*='birth' i]",
				"input[autocomplete='bday']",
			},
			Patterns: []string{"dob", "birth", "bday"},
		},
	}
}

// tryFillField attempts to fill a field using multiple strategies
func (f *FormFiller) tryFillField(ctx context.Context, mapping FieldMapping) bool {
	// Strategy 1: Try exact selectors
	for _, selector := range mapping.Selectors {
		if f.fillSelector(ctx, selector, mapping.ProfileValue) {
			return true
		}
	}

	// Strategy 2: Try pattern matching on all input fields
	if f.fillByPattern(ctx, mapping) {
		return true
	}

	return false
}

// fillSelector attempts to fill a specific CSS selector
func (f *FormFiller) fillSelector(ctx context.Context, selector string, value string) bool {
	// Check if element exists and is visible
	var exists bool
	err := chromedp.Run(ctx, chromedp.Evaluate(
		fmt.Sprintf(`(function() {
			var el = document.querySelector("%s");
			return el !== null && el.offsetParent !== null;
		})()`, escapeSelector(selector)),
		&exists,
	))

	if err != nil || !exists {
		return false
	}

	// Clear existing value and fill
	err = chromedp.Run(ctx,
		chromedp.Clear(selector),
		chromedp.SendKeys(selector, value),
	)

	return err == nil
}

// fillByPattern searches for fields matching patterns
func (f *FormFiller) fillByPattern(ctx context.Context, mapping FieldMapping) bool {
	// Build JavaScript to find matching fields
	patternsJS := "["
	for i, p := range mapping.Patterns {
		if i > 0 {
			patternsJS += ","
		}
		patternsJS += fmt.Sprintf(`"%s"`, p)
	}
	patternsJS += "]"

	// JavaScript to find field by pattern
	js := fmt.Sprintf(`(function() {
		var patterns = %s;
		var inputs = document.querySelectorAll('input, select, textarea');
		for (var i = 0; i < inputs.length; i++) {
			var el = inputs[i];
			var name = (el.name || '').toLowerCase();
			var id = (el.id || '').toLowerCase();
			var placeholder = (el.placeholder || '').toLowerCase();
			var label = '';

			// Check for associated label
			if (el.id) {
				var labelEl = document.querySelector('label[for="' + el.id + '"]');
				if (labelEl) label = labelEl.textContent.toLowerCase();
			}

			for (var j = 0; j < patterns.length; j++) {
				var p = patterns[j];
				if (name.includes(p) || id.includes(p) || placeholder.includes(p) || label.includes(p)) {
					if (el.offsetParent !== null) { // is visible
						return {found: true, selector: el.tagName.toLowerCase() + (el.id ? '#' + el.id : (el.name ? '[name="' + el.name + '"]' : ''))};
					}
				}
			}
		}
		return {found: false};
	})()`, patternsJS)

	var result map[string]interface{}
	err := chromedp.Run(ctx, chromedp.Evaluate(js, &result))
	if err != nil {
		return false
	}

	found, ok := result["found"].(bool)
	if !ok || !found {
		return false
	}

	selector, ok := result["selector"].(string)
	if !ok || selector == "" {
		return false
	}

	return f.fillSelector(ctx, selector, mapping.ProfileValue)
}

// FillDropdown fills a select/dropdown field
func (f *FormFiller) FillDropdown(ctx context.Context, selector string, value string) bool {
	// Try to match by value or text
	js := fmt.Sprintf(`(function() {
		var select = document.querySelector("%s");
		if (!select) return false;

		var value = "%s".toLowerCase();
		for (var i = 0; i < select.options.length; i++) {
			var opt = select.options[i];
			if (opt.value.toLowerCase() === value ||
				opt.text.toLowerCase() === value ||
				opt.value.toLowerCase().includes(value) ||
				opt.text.toLowerCase().includes(value)) {
				select.value = opt.value;
				select.dispatchEvent(new Event('change', { bubbles: true }));
				return true;
			}
		}
		return false;
	})()`, escapeSelector(selector), value)

	var success bool
	err := chromedp.Run(ctx, chromedp.Evaluate(js, &success))
	return err == nil && success
}

// CheckCheckbox checks a checkbox if found
func (f *FormFiller) CheckCheckbox(ctx context.Context, selector string) bool {
	js := fmt.Sprintf(`(function() {
		var el = document.querySelector("%s");
		if (el && el.type === 'checkbox' && !el.checked) {
			el.checked = true;
			el.dispatchEvent(new Event('change', { bubbles: true }));
			return true;
		}
		return false;
	})()`, escapeSelector(selector))

	var success bool
	err := chromedp.Run(ctx, chromedp.Evaluate(js, &success))
	return err == nil && success
}

// DetectFormFields returns a list of all form fields on the page
func (f *FormFiller) DetectFormFields(ctx context.Context) ([]FormField, error) {
	js := `(function() {
		var fields = [];
		var inputs = document.querySelectorAll('input, select, textarea');
		for (var i = 0; i < inputs.length; i++) {
			var el = inputs[i];
			if (el.type === 'hidden' || el.type === 'submit' || el.type === 'button') continue;

			var label = '';
			if (el.id) {
				var labelEl = document.querySelector('label[for="' + el.id + '"]');
				if (labelEl) label = labelEl.textContent.trim();
			}

			fields.push({
				tag: el.tagName.toLowerCase(),
				type: el.type || '',
				name: el.name || '',
				id: el.id || '',
				placeholder: el.placeholder || '',
				label: label,
				required: el.required,
				visible: el.offsetParent !== null
			});
		}
		return fields;
	})()`

	var fields []FormField
	err := chromedp.Run(ctx, chromedp.Evaluate(js, &fields))
	return fields, err
}

// FormField represents a detected form field
type FormField struct {
	Tag         string `json:"tag"`
	Type        string `json:"type"`
	Name        string `json:"name"`
	ID          string `json:"id"`
	Placeholder string `json:"placeholder"`
	Label       string `json:"label"`
	Required    bool   `json:"required"`
	Visible     bool   `json:"visible"`
}

// escapeSelector escapes special characters in CSS selectors for JS strings
func escapeSelector(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
