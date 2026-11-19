package config

import (
	"fmt"
	"strings"
)

// Values accepted in options.disclose. Name and email are always sent; every
// other profile field is withheld from removal emails unless listed.
const (
	DiscloseLocation      = "location"       // city, state, ZIP/postal code, country
	DiscloseStreetAddress = "street_address" // implies location
	DisclosePhone         = "phone"
	DiscloseDateOfBirth   = "date_of_birth"
)

// Disclosure says which optional profile fields go into removal emails.
// The zero value discloses only name and email.
type Disclosure struct {
	Location      bool
	StreetAddress bool
	Phone         bool
	DateOfBirth   bool
}

// ParseDisclosure parses options.disclose.
func ParseDisclosure(values []string) (Disclosure, error) {
	var d Disclosure
	for _, v := range values {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case DiscloseLocation:
			d.Location = true
		case DiscloseStreetAddress:
			d.StreetAddress = true
			d.Location = true // a street address is useless without the city
		case DisclosePhone:
			d.Phone = true
		case DiscloseDateOfBirth:
			d.DateOfBirth = true
		case "name", "email":
			return Disclosure{}, fmt.Errorf("options.disclose: %q is always included; remove it", v)
		default:
			return Disclosure{}, fmt.Errorf("options.disclose: unknown disclose value %q (want %s, %s, %s, or %s)",
				v, DiscloseLocation, DiscloseStreetAddress, DisclosePhone, DiscloseDateOfBirth)
		}
	}
	return d, nil
}

// Disclosure parses the configured disclose list.
func (o Options) Disclosure() (Disclosure, error) {
	return ParseDisclosure(o.Disclose)
}

// Union discloses everything either d or e discloses.
func (d Disclosure) Union(e Disclosure) Disclosure {
	return Disclosure{
		Location:      d.Location || e.Location,
		StreetAddress: d.StreetAddress || e.StreetAddress,
		Phone:         d.Phone || e.Phone,
		DateOfBirth:   d.DateOfBirth || e.DateOfBirth,
	}
}

// Apply returns a copy of p with undisclosed fields cleared.
func (d Disclosure) Apply(p Profile) Profile {
	out := Profile{FirstName: p.FirstName, LastName: p.LastName, Email: p.Email}
	if d.Location {
		out.City, out.State, out.ZipCode, out.Country = p.City, p.State, p.ZipCode, p.Country
	}
	if d.StreetAddress {
		out.Address = p.Address
	}
	if d.Phone {
		out.Phone = p.Phone
	}
	if d.DateOfBirth {
		out.DateOfBirth = p.DateOfBirth
	}
	return out
}

// Fields lists what is disclosed, for display.
func (d Disclosure) Fields() []string {
	return append([]string{"name", "email"}, d.Values()...)
}

// Values returns the options.disclose list for d, in a fixed order.
func (d Disclosure) Values() []string {
	var values []string
	if d.Location {
		values = append(values, DiscloseLocation)
	}
	if d.StreetAddress {
		values = append(values, DiscloseStreetAddress)
	}
	if d.Phone {
		values = append(values, DisclosePhone)
	}
	if d.DateOfBirth {
		values = append(values, DiscloseDateOfBirth)
	}
	return values
}

// Withheld lists disclose values for profile fields that are filled in but
// not being sent, so the user can see what they could opt into.
func (d Disclosure) Withheld(p Profile) []string {
	var out []string
	if !d.Location && (p.City != "" || p.State != "" || p.ZipCode != "" || p.Country != "") {
		out = append(out, DiscloseLocation)
	}
	if !d.StreetAddress && p.Address != "" {
		out = append(out, DiscloseStreetAddress)
	}
	if !d.Phone && p.Phone != "" {
		out = append(out, DisclosePhone)
	}
	if !d.DateOfBirth && p.DateOfBirth != "" {
		out = append(out, DiscloseDateOfBirth)
	}
	return out
}
