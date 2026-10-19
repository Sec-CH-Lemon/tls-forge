package harness

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
)

// HellosFixture is what testdata/chrome155-hellos.json holds: the order of
// the extensions of the first ClientHello a browser sent to each of many
// names, each on a connection of its own, launch by launch.
type HellosFixture struct {
	// Browser says which browser was measured, how it was run and where.
	Browser string `json:"browser"`
	// Measured are the dates it was, and How says how.
	Measured string `json:"measured"`
	How      string `json:"how"`
	// Launches are the hellos of each launch in the order they came, each
	// its extensions' code points as sent, GREASE's too, comma-separated.
	Launches [][]string `json:"launches"`
}

// LoadHellos reads a fixture of hellos.
func LoadHellos(path string) (*HellosFixture, error) { return load[HellosFixture](path) }

// Write writes the fixture to path as it is kept, as the fixture of requests
// is.
func (f *HellosFixture) Write(path string) error { return writeJSON(path, f) }

// The launches a measurement of hellos makes, and the names each asks: two
// launches of 200, the second a holdout of the first, which at a false alarm
// of about 0.001 for each statistic tell a uniform order from one that keeps
// an extension where a reference has it twice as often (OrderStats).
const (
	helloLaunches = 2
	helloNames    = 200
)

// sentHello is a ClientHello as the server read it: the name it asked for
// and its extensions' code points, in order.
type sentHello struct {
	name       string
	extensions []uint16
}

// hello keeps the ClientHello of a connection, and has its TLS go on as
// configured.
func (s *Server) hello(info *tls.ClientHelloInfo) (*tls.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hellos = append(s.hellos, sentHello{name: info.ServerName, extensions: slices.Clone(info.Extensions)})
	return nil, nil
}

// helloName is the name the hellos page asks of its i-th connection.
func helloName(i int) string { return "h" + strconv.Itoa(i) + ".example.com" }

// helloScript has the run page ask n names of the bench's TLS port, one after
// another: each a connection of its own, and a first ClientHello.
func helloScript(n int) string {
	return "(async()=>{for(let i=0;i<" + strconv.Itoa(n) + ";i++){" +
		"await fetch('https://h'+i+'.example.com:{P}/p/hello',{mode:'no-cors'}).catch(()=>0)}})().then(done);"
}

// helloOrders are the orders of the first ClientHello sent to each of the n
// names the hellos page asks, in the order asked, each as HellosFixture keeps
// it; or which name had none.
func (s *Server) helloOrders(n int) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, n)
	for i := range n {
		at := slices.IndexFunc(s.hellos, func(h sentHello) bool { return h.name == helloName(i) })
		if at < 0 {
			return nil, fmt.Errorf("no ClientHello asked for %s", helloName(i))
		}
		codes := make([]string, len(s.hellos[at].extensions))
		for j, code := range s.hellos[at].extensions {
			codes[j] = strconv.Itoa(int(code))
		}
		out = append(out, strings.Join(codes, ","))
	}
	return out, nil
}

// MeasureHellos is the order of the extensions of the first ClientHello b
// sends to each of 200 names, launch by launch, of two launches: what the
// fixture of hellos holds. It says each launch to progress, when there is
// one.
func MeasureHellos(ctx context.Context, b Browser, progress io.Writer) ([][]string, error) {
	return measureHellos(ctx, b, helloLaunches, helloNames, measured, progress)
}

func measureHellos(ctx context.Context, b Browser, launches, n int, t timing, progress io.Writer) ([][]string, error) {
	scenarios := map[string]scenario{"hellos": {note: "a page asking names of the bench one after another",
		script: helloScript(n)}}
	s, err := startServer(scenarios)
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.Close() }()
	if progress == nil {
		progress = io.Discard
	}
	var out [][]string
	for launch := 1; launch <= launches; launch++ {
		if _, err := s.run(ctx, b, "hellos", scenarios["hellos"], origins(s.H2, s.Plain), t); err != nil {
			return nil, fmt.Errorf("harness: hellos, launch %d: %w", launch, err)
		}
		orders, err := s.helloOrders(n)
		if err != nil {
			return nil, fmt.Errorf("harness: hellos, launch %d: %w", launch, err)
		}
		out = append(out, orders)
		_, _ = fmt.Fprintf(progress, "hellos, launch %d: %d\n", launch, len(orders))
	}
	return out, nil
}

// ParseOrder reads an order as HellosFixture keeps it.
func ParseOrder(order string) ([]uint16, error) {
	var out []uint16
	for code := range strings.SplitSeq(order, ",") {
		n, err := strconv.ParseUint(code, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("harness: an order of extensions: %q", order)
		}
		out = append(out, uint16(n))
	}
	return out, nil
}

// stays reports an extension that keeps its place when Chromium draws an
// order: GREASE, padding and pre_shared_key. GREASE is said as one code
// point, whichever it drew.
func stays(code uint16) (uint16, bool) {
	switch {
	case code&0x0f0f == 0x0a0a:
		return 0x0a0a, true
	case code == 21, code == 41:
		return code, true
	}
	return code, false
}

// OrderStats are what a sample of extension orders says of how they were
// drawn, against a reference order of the same extensions: the extensions
// that move (all but those stays names) and where they stood in it.
type OrderStats struct {
	// Hellos is how many orders were read, Movable how many extensions each
	// moves.
	Hellos, Movable int
	// FixedPoints is the mean number of moving extensions at the place the
	// reference has them: 1 for every order as likely as any other.
	FixedPoints float64
	// ChiSquare is Pearson's statistic of the moving extensions' places
	// against every place as likely, of (Movable-1)^2 degrees of freedom.
	ChiSquare float64
	// Precedence is the largest distance from one half, over every two
	// moving extensions, of the share of orders in which the one the
	// reference has first comes first.
	Precedence float64
}

// OrderStatsOf reads orders against reference; an order with other
// extensions than the reference's, or those that stay elsewhere, is an
// error.
func OrderStatsOf(orders [][]uint16, reference []uint16) (OrderStats, error) {
	var moving []uint16
	for _, code := range reference {
		if _, fixed := stays(code); !fixed {
			moving = append(moving, code)
		}
	}
	k := len(moving)
	stats := OrderStats{Hellos: len(orders), Movable: k}
	if k < 2 || len(orders) == 0 {
		return stats, fmt.Errorf("harness: %d orders of %d extensions that move: nothing to read", len(orders), k)
	}
	counts := make([][]int, k)
	for i := range counts {
		counts[i] = make([]int, k)
	}
	before := make([][]int, k)
	for i := range before {
		before[i] = make([]int, k)
	}
	fixedPoints := 0
	for n, order := range orders {
		if len(order) != len(reference) {
			return stats, fmt.Errorf("harness: order %d has %d extensions, the reference %d", n+1, len(order), len(reference))
		}
		var perm []int
		for at, code := range order {
			wantCode, wantFixed := stays(reference[at])
			gotCode, gotFixed := stays(code)
			if wantFixed || gotFixed {
				if wantFixed != gotFixed || wantCode != gotCode {
					return stats, fmt.Errorf("harness: order %d has %d where the reference has %d", n+1, code, reference[at])
				}
				continue
			}
			index := slices.Index(moving, code)
			if index < 0 || slices.Contains(perm, index) {
				return stats, fmt.Errorf("harness: order %d has %d, which the reference has not, or twice", n+1, code)
			}
			perm = append(perm, index)
		}
		for place, index := range perm {
			counts[index][place]++
			if index == place {
				fixedPoints++
			}
			for _, later := range perm[place+1:] {
				before[index][later]++
			}
		}
	}
	n := float64(len(orders))
	stats.FixedPoints = float64(fixedPoints) / n
	expected := n / float64(k)
	for _, row := range counts {
		for _, c := range row {
			stats.ChiSquare += (float64(c) - expected) * (float64(c) - expected) / expected
		}
	}
	for a := range k {
		for b := a + 1; b < k; b++ {
			stats.Precedence = max(stats.Precedence, math.Abs(float64(before[a][b])/n-0.5))
		}
	}
	return stats, nil
}

// The z-scores the decision rule takes: about 0.001 one-sided for the
// chi-square, and for the precedence of any of the 136 pairs of Chrome's 17
// moving extensions after Bonferroni's correction; the fixed points within
// four standard errors, their variance being 1 for a uniform order.
const (
	chiSquareZ  = 3.09
	precedenceZ = 4.5
	fixedPointZ = 4.0
)

// Problems are how the stats stand against every order being as likely as
// any other, at a false alarm of about 0.001 for each statistic; nothing
// when they do not.
func (o OrderStats) Problems() []string {
	var out []string
	n := float64(o.Hellos)
	if bound := fixedPointZ / math.Sqrt(n); math.Abs(o.FixedPoints-1) > bound {
		out = append(out, fmt.Sprintf("%d orders keep %.3f extensions where the reference has them, not 1 within %.3f",
			o.Hellos, o.FixedPoints, bound))
	}
	if bound := chiSquareBound(float64((o.Movable - 1) * (o.Movable - 1))); o.ChiSquare > bound {
		out = append(out, fmt.Sprintf("%d orders put the extensions in places as unevenly as chi-square %.1f, past %.1f",
			o.Hellos, o.ChiSquare, bound))
	}
	if bound := precedenceZ * 0.5 / math.Sqrt(n); o.Precedence > bound {
		out = append(out, fmt.Sprintf("%d orders put one extension before another %.3f from one half, past %.3f",
			o.Hellos, o.Precedence, bound))
	}
	return out
}

// chiSquareBound is the chi-square of df degrees of freedom passed about once
// in a thousand, by Wilson and Hilferty's approximation.
func chiSquareBound(df float64) float64 {
	v := 2 / (9 * df)
	return df * math.Pow(1-v+chiSquareZ*math.Sqrt(v), 3)
}
