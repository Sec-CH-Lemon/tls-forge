package harness

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// helloBrowser is a browser that does what the hellos page asks: a
// connection to each of n names on the bench's TLS port, one after another,
// then done. On its open-th launch, counted from 1, it passes over the name
// skip names.
type helloBrowser struct {
	n      int
	fail   bool
	opened *int
	skip   map[int]int
}

func (b helloBrowser) Open(_ context.Context, page, _ string) (func(), error) {
	if b.fail {
		return nil, errors.New("the fake would not open " + page)
	}
	*b.opened++
	skip, skips := b.skip[*b.opened]
	u, _ := url.Parse(page)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range b.n {
			if skips && i == skip {
				continue
			}
			conn, err := tls.Dial("tcp", "127.0.0.1:"+u.Port(),
				&tls.Config{ServerName: helloName(i), InsecureSkipVerify: true}) //nolint:gosec // the bench's own
			if err == nil {
				_ = conn.Close()
			}
		}
		c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:"+u.Port())
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // the bench's own certificate
		}}
		if res, err := c.Get(u.Scheme + "://" + u.Host + "/done/hellos"); err == nil {
			_ = res.Body.Close()
		}
	}()
	return func() { <-done }, nil
}

func (b helloBrowser) DumpDOM(context.Context, string) ([]byte, error) { return nil, nil }

func TestTheHellosAreMeasuredLaunchByLaunch(t *testing.T) {
	var progress bytes.Buffer
	got, err := measureHellos(context.Background(), helloBrowser{n: 3, opened: new(int)}, 2, 3, quick, &progress)
	if err != nil {
		t.Fatalf("measureHellos: %v", err)
	}
	if len(got) != 2 || len(got[0]) != 3 || len(got[1]) != 3 ||
		progress.String() != "hellos, launch 1: 3\nhellos, launch 2: 3\n" {
		t.Fatalf("measured %q, said %q", got, progress.String())
	}
	for _, launch := range got {
		for _, order := range launch {
			if codes, err := ParseOrder(order); err != nil || len(codes) < 3 || !slices.Contains(codes, 0) {
				t.Errorf("an order %q: %v, %v", order, codes, err)
			}
		}
	}
	// Each launch reads its own hellos alone: one that passes over a name has
	// none of it, the launch before's aside.
	if _, err := measureHellos(context.Background(), helloBrowser{n: 3, opened: new(int), skip: map[int]int{2: 1}}, 2, 3,
		quick, nil); err == nil || err.Error() != "harness: hellos, launch 2: no ClientHello asked for h1.example.com" {
		t.Errorf("a name passed over: %v", err)
	}
	if _, err := measureHellos(context.Background(), helloBrowser{fail: true}, 1, 3, quick, nil); err == nil ||
		!strings.HasPrefix(err.Error(), "harness: hellos, launch 1: the fake would not open https://www.example.com:") {
		t.Errorf("a browser that does not open: %v", err)
	}
	failing := errors.New("no port")
	old := listen
	listen = func(string, string) (net.Listener, error) { return nil, failing }
	t.Cleanup(func() { listen = old })
	if _, err := MeasureHellos(context.Background(), helloBrowser{}, nil); !errors.Is(err, failing) {
		t.Errorf("measured with no server: %v", err)
	}
}

func TestTheHellosPageAsksEachNameOnItsOwn(t *testing.T) {
	if got := helloScript(2); got != "(async()=>{for(let i=0;i<2;i++){"+
		"await fetch('https://h'+i+'.example.com:{P}/p/hello',{mode:'no-cors'}).catch(()=>0)}})().then(done);" {
		t.Errorf("helloScript(2) = %q", got)
	}
	if helloName(7) != "h7.example.com" {
		t.Errorf("helloName(7) = %q", helloName(7))
	}
}

func TestAnOrderIsReadAsTheFixtureKeepsIt(t *testing.T) {
	if got, err := ParseOrder("2570,0,65535"); err != nil || !slices.Equal(got, []uint16{2570, 0, 65535}) {
		t.Errorf("ParseOrder = %v, %v", got, err)
	}
	for _, bad := range []string{"", "1,,2", "1,x", "65536", "-1"} {
		if _, err := ParseOrder(bad); err == nil || err.Error() != `harness: an order of extensions: "`+bad+`"` {
			t.Errorf("ParseOrder(%q): %v", bad, err)
		}
	}
}

// greased is order with a GREASE first and last, a different one each time,
// as Chrome draws them.
func greased(order ...uint16) []uint16 {
	return append(append([]uint16{0x1a1a}, order...), 0x5a5a)
}

func TestOrderStatsSayHowOrdersWereDrawn(t *testing.T) {
	reference := []uint16{0x0a0a, 1, 2, 21, 3, 0x0a0a, 41}
	with := func(a, b, c uint16) []uint16 { return []uint16{0x2a2a, a, b, 21, c, 0x3a3a, 41} }
	// Every order of three as often: as uniform as can be.
	var all [][]uint16
	for _, p := range [][3]uint16{{1, 2, 3}, {1, 3, 2}, {2, 1, 3}, {2, 3, 1}, {3, 1, 2}, {3, 2, 1}} {
		all = append(all, with(p[0], p[1], p[2]))
	}
	stats, err := OrderStatsOf(all, reference)
	if err != nil || stats != (OrderStats{Hellos: 6, Movable: 3, FixedPoints: 1}) || stats.Problems() != nil {
		t.Errorf("every order: %+v, %v, %q", stats, err, stats.Problems())
	}
	// The reference's every time: all three wrong.
	// Each extension at its place 100 times of an expected 33.3, and 0 times
	// at each other.
	same := slices.Repeat([][]uint16{with(1, 2, 3)}, 100)
	stats, err = OrderStatsOf(same, reference)
	if err != nil || stats.Hellos != 100 || stats.Movable != 3 || stats.FixedPoints != 3 ||
		math.Abs(stats.ChiSquare-600) > 1e-9 || stats.Precedence != 0.5 {
		t.Fatalf("the same order: %+v, %v", stats, err)
	}
	if problems := stats.Problems(); !slices.Equal(problems, []string{
		"100 orders keep 3.000 extensions where the reference has them, not 1 within 0.400",
		"100 orders put the extensions in places as unevenly as chi-square 600.0, past 18.7",
		"100 orders put one extension before another 0.500 from one half, past 0.225",
	}) {
		t.Errorf("Problems = %q", problems)
	}
	// The other way round every time, and never an extension at its place:
	// as far from it, one way and the other.
	reversed := slices.Repeat([][]uint16{with(3, 2, 1)}, 100)
	if stats, err := OrderStatsOf(reversed, reference); err != nil || stats.Precedence != 0.5 || stats.FixedPoints != 1 {
		t.Errorf("reversed: %+v, %v", stats, err)
	}
	shifted := slices.Concat(slices.Repeat([][]uint16{with(2, 3, 1)}, 50), slices.Repeat([][]uint16{with(3, 1, 2)}, 50))
	stats, err = OrderStatsOf(shifted, reference)
	if problems := stats.Problems(); err != nil || stats.FixedPoints != 0 || len(problems) == 0 ||
		problems[0] != "100 orders keep 0.000 extensions where the reference has them, not 1 within 0.400" {
		t.Errorf("shifted: %+v, %v, %q", stats, err, problems)
	}
	// What cannot be read.
	for _, tc := range []struct {
		orders    [][]uint16
		reference []uint16
		says      string
	}{
		{all, []uint16{0x0a0a, 1, 41}, "harness: 6 orders of 1 extensions that move: nothing to read"},
		{nil, reference, "harness: 0 orders of 3 extensions that move: nothing to read"},
		{[][]uint16{{0x0a0a, 1, 2, 21, 3}}, reference, "harness: order 1 has 5 extensions, the reference 7"},
		{[][]uint16{all[0], with(1, 2, 3)[:6]}, reference, "harness: order 2 has 6 extensions, the reference 7"},
		{[][]uint16{{1, 0x0a0a, 2, 21, 3, 0x0a0a, 41}}, reference, "harness: order 1 has 1 where the reference has 2570"},
		{[][]uint16{{0x0a0a, 21, 2, 1, 3, 0x0a0a, 41}}, reference, "harness: order 1 has 21 where the reference has 1"},
		{[][]uint16{with(1, 2, 4)}, reference, "harness: order 1 has 4, which the reference has not, or twice"},
		{[][]uint16{with(1, 1, 3)}, reference, "harness: order 1 has 1, which the reference has not, or twice"},
	} {
		if _, err := OrderStatsOf(tc.orders, tc.reference); err == nil || err.Error() != tc.says {
			t.Errorf("%v: %v, want %q", tc.orders, err, tc.says)
		}
	}
	// GREASE is any of its code points, padding and pre_shared_key stay.
	if _, err := OrderStatsOf([][]uint16{greased(2, 1)}, greased(1, 2)); err != nil {
		t.Errorf("GREASE drawn afresh: %v", err)
	}
}

func TestTheChiSquareBoundIsTheThousandthPoint(t *testing.T) {
	// Of 256 degrees of freedom, Chrome's 17 extensions, 330.5 by the
	// tables, and of 4 18.47: the approximation is a little above, so a
	// little more than a thousandth of uniform samples passes.
	for df, want := range map[float64]float64{256: 331.7, 4: 18.7} {
		if got := chiSquareBound(df); math.Abs(got-want) > 0.05 {
			t.Errorf("chiSquareBound(%v) = %.2f, want %.1f", df, got, want)
		}
	}
}

func TestAFixtureOfHellosIsWrittenAsItIsKept(t *testing.T) {
	// The committed fixture reads, and writes back byte for byte.
	kept, err := os.ReadFile("../../testdata/chrome155-hellos.json")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	fixture, err := LoadHellos("../../testdata/chrome155-hellos.json")
	if err != nil {
		t.Fatalf("LoadHellos: %v", err)
	}
	path := filepath.Join(t.TempDir(), "hellos.json")
	if err := fixture.Write(path); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if wrote, _ := os.ReadFile(path); !bytes.Equal(wrote, kept) {
		t.Errorf("wrote it otherwise:\n%s", wrote)
	}
	if len(fixture.Launches) != helloLaunches {
		t.Fatalf("%d launches", len(fixture.Launches))
	}
	for i, launch := range fixture.Launches {
		if len(launch) != helloNames {
			t.Errorf("launch %d has %d hellos", i+1, len(launch))
		}
	}
}
