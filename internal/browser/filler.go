package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

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

// ErrPageChanged means the page navigated while the form was being filled,
// so filling stopped.
var ErrPageChanged = errors.New("the page navigated while it was being filled; filling stopped")

// Fill fills the form fields the profile has values for. origin is the page
// origin (scheme://host[:port]) that passed the caller's URL check: each
// field is filled only while the page is still there, and filling stops with
// ErrPageChanged once it isn't.
func (f *FormFiller) Fill(ctx context.Context, origin string) (*FillResult, error) {
	result := &FillResult{}
	for _, mapping := range f.getFieldMappings() {
		if mapping.ProfileValue == "" {
			result.MissingFields = append(result.MissingFields, mapping.FieldType)
			continue
		}
		js, err := fillCall(origin, mapping)
		if err != nil {
			return result, err
		}
		status, err := chromedp.Run(ctx, chromedp.Evaluate[string](js))
		if err != nil {
			// e.g. the page is navigating; the next field's origin check decides.
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", mapping.FieldType, err))
			continue
		}
		switch status {
		case "filled":
			result.FilledFields = append(result.FilledFields, mapping.FieldType)
		case "moved":
			return result, ErrPageChanged
		}
	}
	return result, nil
}

// fillCall builds the fillFieldJS call for one mapping. JSON-encoded values
// are valid JavaScript literals.
func fillCall(origin string, m FieldMapping) (string, error) {
	args, err := json.Marshal([]any{origin, m.Selectors, m.Patterns, m.ProfileValue})
	if err != nil {
		return "", fmt.Errorf("encoding %s: %w", m.FieldType, err)
	}
	return fillFieldJS + ".apply(null, " + string(args) + ")", nil
}

// fillFieldJS fills one field and returns "filled", "none" (no usable field),
// or "moved" (the page is no longer on origin). It runs as one script, so the
// page can't navigate between the origin check and the fill.
//
// The field is the first visible, editable one not already filled that
// matches a selector (in order), or else whose name, id, placeholder or label
// contains a pattern. Filled fields are marked, so a later mapping can't
// overwrite them (an address selector also matches "email_address"). The
// value is set directly and input/change events fired, as typing would.
const fillFieldJS = `(function(origin, selectors, patterns, value) {
	if (location.origin !== origin) return "moved";
	function usable(el) {
		return el.offsetParent !== null && !el.disabled && !el.readOnly &&
			!el.hasAttribute('data-eraser-filled') &&
			!/^(hidden|submit|button|reset|checkbox|radio|file|image)$/i.test(el.type || '');
	}
	var target = null;
	for (var i = 0; i < selectors.length && !target; i++) {
		var els = document.querySelectorAll(selectors[i]);
		for (var j = 0; j < els.length; j++) {
			if (usable(els[j])) { target = els[j]; break; }
		}
	}
	if (!target) {
		var fields = document.querySelectorAll('input, select, textarea');
		search: for (var k = 0; k < fields.length; k++) {
			var el = fields[k];
			if (!usable(el)) continue;
			var label = '';
			if (el.id) {
				var l = document.querySelector('label[for="' + CSS.escape(el.id) + '"]');
				if (l) label = l.textContent;
			}
			var text = [el.name, el.id, el.placeholder, label].join(' ').toLowerCase();
			for (var p = 0; p < patterns.length; p++) {
				if (text.indexOf(patterns[p]) !== -1) { target = el; break search; }
			}
		}
	}
	if (!target) return "none";

	if (target.tagName === 'SELECT') {
		var want = value.trim().toLowerCase(), option = null;
		for (var o = 0; o < target.options.length; o++) {
			var opt = target.options[o];
			if (opt.value.toLowerCase() === want || opt.text.trim().toLowerCase() === want) { option = opt; break; }
		}
		if (!option) return "none";
		target.value = option.value;
	} else {
		var proto = target.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
		Object.getOwnPropertyDescriptor(proto, 'value').set.call(target, value);
		if (target.value === '') return "none"; // e.g. a date field rejecting the format
	}
	target.setAttribute('data-eraser-filled', '1');
	target.dispatchEvent(new Event('input', {bubbles: true}));
	target.dispatchEvent(new Event('change', {bubbles: true}));
	return "filled";
})`

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
