package tlsforge

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

func TestA10MissingPoliciesCannotExecuteOrBeSilentlyMigrated(t *testing.T) {
	keys := []string{"http.instance_scope", "http.cache_scope", "http.cache_validators", "cache.duplicate_freshness_policy", "cache.invalid_freshness_policy", "cache.freshness_quoted_values", "cache.delta_seconds_limit", "cache.generated_header_order"}
	requests := 0
	site := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	defer site.Close()
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			p := shippedProfile(t, "chrome_156_macos").Clone()
			delete(p.Behavior, key)
			data, err := p.Save()
			if err != nil {
				t.Fatal(err)
			}
			offline, err := profile.Inspect(data)
			if err != nil || offline.Behavior.Has(key) {
				t.Fatal("archive retagged", err)
			}
			if _, err = profile.Load(data); err == nil || !strings.Contains(err.Error(), key) {
				t.Fatal("load", err)
			}
			if c, e := New(WithProfileValue(p)); e == nil {
				c.Close()
				t.Fatal("constructor bypass")
			}
			c, err := New()
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.profile = p
			if _, err = c.Do(&Request{URL: site.URL}); err == nil || !strings.Contains(err.Error(), key) {
				t.Fatal("Do bypass", err)
			}
			if _, err = c.Fresh(); err == nil || !strings.Contains(err.Error(), key) {
				t.Fatal("Fresh bypass", err)
			}
			if p.Clone().Behavior.Has(key) {
				t.Fatal("clone added absent rule")
			}
		})
	}
	if requests != 0 {
		t.Fatal("network side effects", requests)
	}
}
