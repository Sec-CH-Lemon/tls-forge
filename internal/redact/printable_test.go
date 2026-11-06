package redact

import "testing"

func TestPrintable(t *testing.T) {
	for _, tc := range []struct{ given, want string }{
		{"", ""},
		{"403 Forbidden", "403 Forbidden"},
		{"tab\tstays", "tab\tstays"},
		{"Mozilla/5.0 (Macintosh) Chrome/156", "Mozilla/5.0 (Macintosh) Chrome/156"},
		{"403 \x1b]0;owned\x07title", `403 \x1b]0;owned\atitle`},
		{"403 \x1b[2J\x1b[Hclear", `403 \x1b[2J\x1b[Hclear`},
		{"one\nline\rover", `one\nline\rover`},
		{"del\x7f", `del\x7f`},
		{"c1 \u0085\u009b", `c1 \u0085\u009b`},
		{"zero\x00", `zero\x00`},
		{"кириллица и 漢字", "кириллица и 漢字"},
	} {
		if got := Printable(tc.given); got != tc.want {
			t.Errorf("Printable(%q) = %q, want %q", tc.given, got, tc.want)
		}
	}
}
