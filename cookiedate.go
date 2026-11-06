package tlsforge

import (
	"strconv"
	"strings"
	"time"
)

// cookieMonths are the months a cookie's Expires names, by the prefix it
// begins with.
var cookieMonths = []string{"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"}

// cookieDateDelimiters are what Chromium reads a cookie's Expires as words
// between: anything but a letter, a digit and ':'.
const cookieDateDelimiters = "\t !\"#$%&'()*+,-./;<=>?@[\\]^_`{|}~"

// cookieExpiry is the time a cookie's Expires says, as Chromium's
// ParseCookieExpirationTime reads it (net/cookies/cookie_util.cc, 156): its
// words in any order, a month by its first three letters, a time of three
// numbers and colons, a day of one or two digits and a year of up to five,
// a two-digit year 1970 to 2069, any other word passed over; a time that is
// no time of the calendar is none. False when it says none.
func cookieExpiry(value string) (time.Time, bool) {
	var day, month, year, hour, minute, second int
	var foundDay, foundMonth, foundTime, foundYear bool
	for _, token := range strings.FieldsFunc(value, func(r rune) bool { return strings.ContainsRune(cookieDateDelimiters, r) }) {
		switch {
		case token[0] < '0' || token[0] > '9':
			for i, name := range cookieMonths {
				if !foundMonth && len(token) >= 3 && strings.Map(lowerASCII, token[:3]) == name {
					month, foundMonth = i+1, true
				}
			}
		case strings.Contains(token, ":"):
			parts := strings.Split(token, ":")
			if foundTime || len(parts) != 3 {
				continue
			}
			var hms [3]int
			valid := true
			for i, part := range parts {
				n, err := strconv.ParseUint(part, 10, 32)
				valid = valid && err == nil
				hms[i] = int(n)
			}
			if valid {
				hour, minute, second, foundTime = hms[0], hms[1], hms[2], true
			}
		case !foundDay && len(token) <= 2:
			if n, err := strconv.Atoi(token); err == nil {
				day, foundDay = n, true
			}
		case !foundYear && len(token) <= 5:
			if n, err := strconv.Atoi(token); err == nil {
				year, foundYear = n, true
			}
		}
	}
	if !foundDay || !foundMonth || !foundTime || !foundYear {
		return time.Time{}, false
	}
	switch {
	case year >= 70 && year <= 99:
		year += 1900
	case year >= 0 && year <= 69:
		year += 2000
	}
	// A second past 59 would make another minute, which is held.
	t := time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC)
	if t.Year() != year || int(t.Month()) != month || t.Day() != day || t.Hour() != hour || t.Minute() != minute {
		return time.Time{}, false
	}
	return t, true
}

// cookieExpires is the last Expires of a Set-Cookie's attributes, as
// Chromium's ParsedCookie keeps the last of a name.
func cookieExpires(attributes string) (string, bool) {
	value, found := "", false
	for _, attribute := range strings.Split(attributes, ";") {
		name, v, _ := strings.Cut(attribute, "=")
		if strings.EqualFold(strings.TrimSpace(name), "expires") {
			value, found = strings.TrimSpace(v), true
		}
	}
	return value, found
}
