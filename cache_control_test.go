package tlsforge

import (
	fhttp "github.com/igor-lemon/fhttp"
	"strings"
	"testing"
	"time"
)

func TestCacheControlPreservesOrderedFieldsAndQuotedData(t *testing.T) {
	fields := []string{` max-age=0, EXT="a, no-store, b\"c", MAX-AGE=600 `, "\tno-cache\t"}
	d := cacheDirectives(fhttp.Header{"Cache-Control": fields})
	if len(d) != 4 || d[0].Value != "0" || d[2].Value != "600" || d[3].Field != 1 || !d.has("no-cache") || d.has("no-store") {
		t.Fatalf("%+v", d)
	}
	if d[1].Value != `a, no-store, b"c` || !d[1].Quoted || !d[1].Valid {
		t.Fatal(d[1])
	}
	for i, field := range fields {
		var raw []string
		for _, v := range d {
			if v.Field == i {
				raw = append(raw, v.Raw)
			}
		}
		if strings.Join(raw, ",") != field {
			t.Fatal("lost source", field, raw)
		}
	}
}

func TestCacheFreshnessSelectionIsProfileData(t *testing.T) {
	for _, tt := range []struct {
		raw     string
		seconds int64
		present bool
	}{
		{"max-age=0,max-age=600", 0, true}, {"max-age=600,max-age=0", 600, true},
		{"max-age=bogus,max-age=600", 600, true}, {`max-age="0",max-age=600`, 600, true},
		{`max-age="600"`, 0, false}, {"max-age =600", 0, false}, {"max-age= 600", 0, false},
		{" MaX-AgE=600\t", 600, true}, {"max-age=-1", 0, false}, {"max-age=600oops", 0, false},
		{"max-age=99999999999999999999999999", 4294967295, true},
		{"max-age=99999999999999999999999999x", 0, false},
	} {
		p := cacheOf(t, nil).runtimeBehavior()
		got, ok := cacheDirectives(fhttp.Header{"Cache-Control": {tt.raw}}).seconds("max-age", p)
		if ok != tt.present || got != time.Duration(tt.seconds)*time.Second {
			t.Errorf("%q: %v/%v", tt.raw, got, ok)
		}
	}
	d := cacheDirectives(fhttp.Header{"Cache-Control": {"max-age=600,max-age=600"}})
	if value, ok := d.seconds("max-age", cacheOf(t, map[string]string{"cache.duplicate_freshness_policy": `"stale"`}).runtimeBehavior()); !ok || value != 0 {
		t.Fatal(value, ok)
	}
	if value, ok := cacheDirectives(fhttp.Header{"Cache-Control": {`max-age="600"`}}).seconds("max-age", cacheOf(t, map[string]string{"cache.freshness_quoted_values": `true`}).runtimeBehavior()); !ok || value != 600*time.Second {
		t.Fatal(value, ok)
	}
}

func FuzzCacheControl(f *testing.F) {
	for _, s := range []string{`max-age=0,max-age=600`, `x="a,b\"c",no-store`, `max-age=9999999999999999999999999x`, "\r\n", `x="unterminated, no-store`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		d := cacheDirectives(fhttp.Header{"Cache-Control": {raw}})
		parts := make([]string, 0, len(d))
		for _, v := range d {
			parts = append(parts, v.Raw)
			if v.Field != 0 {
				t.Fatal(v)
			}
			if v.Valid && !cacheToken(v.Name) {
				t.Fatal(v)
			}
		}
		if strings.Join(parts, ",") != raw || len(d) > len(raw)+1 {
			t.Fatal("lost source or unbounded directive count")
		}
		_, _ = cacheDelta(raw, 4294967295)
	})
}

func TestMalformedCacheDirectivesRemainInvalid(t *testing.T) {
	for _, raw := range []string{"", `x="dangling\`, "x=\"a\x00b\"", "x=\"a\nb\""} {
		d := parseCacheDirective(0, raw)
		if d.Valid {
			t.Fatal("accepted", raw, d)
		}
	}
	if _, ok := cacheDelta("", 10); ok {
		t.Fatal("empty delta")
	}
	d := cacheDirectives(fhttp.Header{"Cache-Control": {"x=1,max-age=bogus"}})
	p := cacheOf(t, map[string]string{"cache.invalid_freshness_policy": `"stale"`}).runtimeBehavior()
	if value, ok := d.seconds("max-age", p); !ok || value != 0 {
		t.Fatal(value, ok)
	}
}
