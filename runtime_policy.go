package tlsforge

import (
	"fmt"
	"github.com/Sec-CH-Lemon/tls-forge/v5/profile"
	"github.com/igor-lemon/fhttp/http2"
	"github.com/igor-lemon/utls/behavior"
	"strings"
	"time"
)

func legacyPolicy() behavior.Policy { return profile.LegacyBehavior() }
func policyArgument(p []behavior.Policy) behavior.Policy {
	if len(p) > 0 {
		return p[0]
	}
	return legacyPolicy()
}
func (c *Client) behavior() behavior.Policy {
	if c == nil || c.profile == nil {
		return legacyPolicy()
	}
	return c.profile.RuntimeBehavior()
}
func policyDuration(p behavior.Policy, key string) time.Duration {
	return time.Duration(p.Uint(key)) * time.Millisecond
}
func priorityFrom(p behavior.Policy, prefix string) http2.PriorityParam {
	return http2.PriorityParam{Weight: uint8(p.Uint(prefix + "_weight")), Exclusive: p.Flag(prefix + "_exclusive")}
}
func ordinal(n int) string {
	suffix := "th"
	if n%100 < 11 || n%100 > 13 {
		switch n % 10 {
		case 1:
			suffix = "st"
		case 2:
			suffix = "nd"
		case 3:
			suffix = "rd"
		}
	}
	return fmt.Sprintf("%d%s", n, suffix)
}

func hasPrefixIn(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
