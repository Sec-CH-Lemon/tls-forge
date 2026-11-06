package redact

import (
	"strconv"
	"strings"
	"unicode"
)

// Printable is text as a terminal may be given it: every control character
// in it but a tab (C0, DEL and C1, a newline and a carriage return among
// them) written as Go writes it in a quoted string, and nothing else changed.
// What a server, a proxy or a visiting browser said is not to move the
// cursor, clear the screen, set a window's title or start a line of its own.
func Printable(text string) string {
	if !strings.ContainsFunc(text, controls) {
		return text
	}
	var b strings.Builder
	for _, r := range text {
		if controls(r) {
			quoted := strconv.QuoteRune(r)
			b.WriteString(quoted[1 : len(quoted)-1])
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func controls(r rune) bool { return r != '\t' && unicode.IsControl(r) }
