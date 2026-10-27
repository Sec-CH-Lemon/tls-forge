package profile

import (
	"fmt"
	"github.com/Sec-CH-Lemon/tls-forge/engine"
	"github.com/igor-lemon/utls/behavior"
	"slices"
)

// RuntimeBehavior is the explicit data consumed by all network layers.
// Schema 0-2 compatibility is materialized on load/save, never for schema 3.
func (p *Profile) RuntimeBehavior() behavior.Policy {
	if p == nil {
		return nil
	}
	if p.Behavior != nil {
		return p.Behavior
	}
	if p.Schema < 3 {
		if p.chromium() {
			pol := behavior.Legacy()
			_, platform := Split(p.Name)
			if platform == "windows" {
				pol["http.negotiate_auth"] = []byte("true")
			}
			return pol
		}
		return behavior.Generic()
	}
	return nil
}

// requiredRules are what no executable profile of this engine runs without.
var requiredRules = []string{"http.max_content_codings", "http.content_coding_overflow", "http.ignored_content_codings", "cookie.prefixes"}

// LegacyBehavior is for migration and standalone compatibility helpers only.
func LegacyBehavior() behavior.Policy { return behavior.Legacy() }

func (p *Profile) validateBehavior() error {
	return p.validateBehaviorFor(true)
}

// Offline inspection and serialization preserve archives from earlier states
// of the same unpublished major. They do not grant permission to execute them.
func (p *Profile) validateBehaviorFor(execution bool) error {
	if p.Schema >= 3 && p.Behavior == nil {
		return fmt.Errorf("profile %q: schema 3 requires an explicit behavior object", p.Name)
	}
	if err := p.RuntimeBehavior().Validate(); err != nil {
		return fmt.Errorf("profile %q: %w", p.Name, err)
	}
	if execution && p.EngineMajor != nil && *p.EngineMajor == engine.Major() {
		// Whatever schema a profile says, and whether the behavior it runs
		// with is its own or an older format's data, it does not run without
		// the rules these hold: how deep a body's codings go, and which
		// cookies a server may set. Without them a body would fail to decode,
		// and a prefix would protect nothing.
		pol := p.RuntimeBehavior()
		for _, key := range requiredRules {
			if !pol.Has(key) {
				return fmt.Errorf("profile %q: behavior is incomplete; requires %s", p.Name, key)
			}
		}
	}
	if p.Schema >= 3 {
		if p.EngineMajor != nil && *p.EngineMajor == engine.Major() {
			for _, key := range []string{"http.zero_content_length_methods", "http.content_length_empty_body", "h1.zero_length_identity", "h1.zero_length_identity_excluded_methods", "h2.read_loop_start", "h3.grease_payload_lengths", "h3.control_order", "h3.priority_updates", "h3.priority_source", "h3.qpack.huffman_names", "h3.qpack.error_invalid_relative_index_reason", "h3.qpack.error_capacity_exceeded_reason", "h3.qpack.error_zero_increment_reason", "h3.qpack.error_decompression_reason", "h3.qpack.error_encoder_reason", "h3.qpack.error_decoder_reason", "h3.qpack.error_stream_unavailable_reason", "h3.qpack.error_stream_write_reason", "h3.qpack.error_queue_exhausted_reason", "h3.qpack.huffman_values", "h3.qpack.encoder_strategy", "h3.qpack.decoder_feedback", "h3.qpack.never_index", "h3.qpack.streams", "h3.qpack.stream_order", "h3.qpack.encoder_warmup_sections", "h3.qpack.reference_base", "h3.qpack.encoder_table_bytes", "h3.qpack.draining_percent", "h3.qpack.critical_close_space", "h3.qpack.critical_close_code", "h3.retry_attempts", "h3.retry_unprocessed_attempts", "h3.retry_methods", "h3.retry_application_errors", "h3.retry_transport_errors", "h3.qpack.critical_close_frame_type", "h3.qpack.critical_close_reason"} {
				if !p.Behavior.Has(key) {
					return fmt.Errorf("profile %q: behavior is incomplete; requires %s", p.Name, key)
				}
			}
		}
		if p.Behavior.Has("tls.ech_payload_lengths") {
			return fmt.Errorf("profile %q: ECH lengths belong in per_connection.ech_payload_lengths", p.Name)
		}
		for _, key := range []string{"http.max_site_pools", "http.body_read_bytes", "http.zstd_window_bytes", "http.content_codings", "http.gzip_decoder", "http.redirects_navigation", "http.redirects_fetch", "http.max_auth_restarts", "http.auth_cache_entries", "http.auth_cache_paths", "http.auth_scheme_order", "cache.entry_bytes", "cache.total_bytes", "cache.entries"} {
			if !p.Behavior.Has(key) {
				return fmt.Errorf("profile %q: behavior is incomplete; requires %s", p.Name, key)
			}
		}
	}
	return nil
}

// HintOrder is the order the profile sends its client hints in, as its
// behavior's headers.client_hint_order says.
func (p *Profile) HintOrder() []string {
	return p.RuntimeBehavior().Strings("headers.client_hint_order")
}

// AskedHints are the hints of HintOrder that go only to a server that asks
// for them: all but the profile's headers.default_client_hints.
func (p *Profile) AskedHints() []string {
	var out []string
	defaults := p.RuntimeBehavior().Strings("headers.default_client_hints")
	for _, name := range p.HintOrder() {
		if !slices.Contains(defaults, name) {
			out = append(out, name)
		}
	}
	return out
}
