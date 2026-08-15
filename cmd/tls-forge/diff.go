package main

import (
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/Sec-CH-Lemon/tls-forge/fingerprint"
)

// Rendering the comparison as a diff.
//
// Green for a field the browser and the client agree on, red for one they do
// not, with the two values on `-` and `+` lines. That is not quite what git
// means by those colours, where red is what was removed and green what was
// added. Here there is nothing being added: there is a browser, a thing
// pretending to be it, and the only question is whether each field matches. So
// the colour answers that question and the markers say which side is which.

// palette is the escape sequences to use, or empty strings when colour is off.
type palette struct {
	match  string
	differ string
	dim    string
	reset  string
}

const (
	ansiGreen = "\x1b[32m"
	ansiRed   = "\x1b[31m"
	ansiDim   = "\x1b[2m"
	ansiReset = "\x1b[0m"
)

// paletteFor decides whether to emit colour.
//
// `auto` means "only when a person is looking": piping the output to a file or
// through grep should not fill it with escape sequences. NO_COLOR is honoured
// because it is the one convention every tool that does this agrees on.
func paletteFor(mode string, w io.Writer) (palette, error) {
	switch mode {
	case "never":
		return palette{}, nil
	case "always":
		return palette{match: ansiGreen, differ: ansiRed, dim: ansiDim, reset: ansiReset}, nil
	case "auto":
		if _, set := os.LookupEnv("NO_COLOR"); set || !isTerminal(w) {
			return palette{}, nil
		}
		return palette{match: ansiGreen, differ: ansiRed, dim: ansiDim, reset: ansiReset}, nil
	default:
		return palette{}, &badFlag{"--color", mode, "auto, always or never"}
	}
}

type badFlag struct{ flag, got, want string }

func (e *badFlag) Error() string {
	return e.flag + " is " + strconv.Quote(e.got) + ", want " + e.want
}

// isTerminal reports whether the writer is a character device, which is the
// portable way to ask without a dependency on a terminal library.
func isTerminal(w io.Writer) bool {
	if p, ok := w.(*printer); ok {
		w = p.w
	}
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// diffWidth is where a matching value is cut short. Wide enough for a JA4,
// narrow enough to stay readable in a split terminal. `-full` turns the
// trimming off.
//
// Only matching values are trimmed. A field that differs is printed whole, even
// if it wraps: the difference is the thing being looked for, and it can sit
// anywhere in the value, including past a cut.
const diffWidth = 96

type diffPrinter struct {
	out     *printer
	colour  palette
	full    bool
	labelAt int
}

// section writes one group of fields, zipped from the two sides.
//
// The two lists come from the same function, so they are the same length and in
// the same order, and the pairing needs no matching logic.
func (d *diffPrinter) section(title string, reference, candidate []fingerprint.Field) {
	d.out.printf("%s%s%s\n", d.colour.dim, title, d.colour.reset)
	for i, want := range reference {
		got := candidate[i]
		if want.Matches(got) {
			d.line(d.colour.match, " ", want.Name, want.Render(), !d.full)
			continue
		}
		d.line(d.colour.differ, "-", want.Name, want.Render(), false)
		d.line(d.colour.differ, "+", got.Name, got.Render(), false)
	}
	d.out.println()
}

func (d *diffPrinter) line(colour, marker, name, value string, trim bool) {
	label := name
	if len(label) < d.labelAt {
		label += strings.Repeat(" ", d.labelAt-len(label))
	}
	if budget := diffWidth - d.labelAt - 2; trim && len(value) > budget {
		value = value[:budget-1] + "…"
	}
	d.out.printf("%s%s %s %s%s\n", colour, marker, label, value, d.colour.reset)
}

// widestLabel keeps the values aligned, which is what makes two long lists
// comparable by eye at all.
func widestLabel(groups ...[]fingerprint.Field) int {
	widest := 0
	for _, group := range groups {
		for _, f := range group {
			if len(f.Name) > widest {
				widest = len(f.Name)
			}
		}
	}
	return widest
}
