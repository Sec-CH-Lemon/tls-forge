package daemon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/Sec-CH-Lemon/tls-forge/v2"
	"strings"
)

// requestNetworkContext checks the new top-level field's exact spelling and
// multiplicity instead of permitting encoding/json last-key-wins semantics.
func requestNetworkContext(line []byte) (*tlsforge.NetworkContext, error) {
	d := json.NewDecoder(bytes.NewReader(line))
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	seen := false
	var value *tlsforge.NetworkContext
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return nil, err
		}
		name := key.(string)
		var raw json.RawMessage
		if err := d.Decode(&raw); err != nil {
			return nil, err
		}
		if strings.EqualFold(name, "network") {
			if seen || name != "network" {
				return nil, fmt.Errorf("duplicate or case-folded network context")
			}
			seen = true
			if !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				var context tlsforge.NetworkContext
				if err := json.Unmarshal(raw, &context); err != nil {
					return nil, fmt.Errorf("network: %w", err)
				}
				value = &context
			}
		}
	}
	return value, nil
}
