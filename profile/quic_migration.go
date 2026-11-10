package profile

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/Sec-CH-Lemon/tls-forge/engine"
	tls "github.com/igor-lemon/utls"
	"github.com/igor-lemon/utls/behavior"
)

//go:embed quic-migration.json
var quicMigrationData []byte

type rawTCPGeneration struct {
	Order string   `json:"extension_order"`
	ECH   []uint16 `json:"ech_payload_lengths"`
}

type quicMigration struct {
	RawTCP struct {
		Chromium rawTCPGeneration `json:"chromium"`
		Generic  rawTCPGeneration `json:"generic"`
	} `json:"raw_tcp_generation"`
	EngineMajor *int   `json:"engine_major"`
	Provenance  string `json:"provenance"`
	CacheSource string `json:"cache_source"`
	Independent struct {
		Behavior behavior.Policy `json:"behavior"`
		Spec     *QUICTLSSpec    `json:"quic_tls_spec"`
		Cached   *QUICTLSSpec    `json:"quic_tls_spec_cached"`
	} `json:"independent"`
	Adapter struct {
		Behavior behavior.Policy `json:"behavior"`
		Copies   []struct {
			From string `json:"from"`
			To   string `json:"to"`
		} `json:"copies"`
	} `json:"adapter"`
	ACK struct {
		Gap struct {
			Present string `json:"present"`
			Absent  string `json:"absent"`
		} `json:"gap"`
		Decimation struct {
			Present string `json:"present"`
			Absent  string `json:"absent"`
		} `json:"decimation"`
	} `json:"ack_selection"`
}

// Migration alone materializes selected legacy mechanisms from pinned data.
// It never runs during ordinary Load/Inspect/Save or turns an export into capture.
func (p *Profile) migrateQUICData(sourceChromium bool) error {
	var m quicMigration
	if err := decodeDescriptorData(quicMigrationData, &m); err != nil {
		return err
	}
	if err := engine.CheckMajor("QUIC migration data", m.EngineMajor); err != nil {
		return err
	}
	if m.CacheSource != "tcp-utls-psk" {
		return fmt.Errorf("unsupported QUIC cache migration source %q", m.CacheSource)
	}
	// What the profile said before: the note below is for a profile the
	// candidate defaults filled in, not one whose QUIC data is its own.
	said := func() string {
		data, _ := json.Marshal([]any{p.Behavior, p.PerConnection, p.QUICTLSSpec})
		return string(data)
	}
	before := said()
	if len(p.ClientHello) > 0 && p.TLSSpec == nil && p.PerConnection == nil {
		generation := m.RawTCP.Generic
		// This is explicit migration of an archived legacy format, not execution.
		if sourceChromium {
			generation = m.RawTCP.Chromium
		}
		if generation.Order != "fixed" && generation.Order != "moving" {
			return fmt.Errorf("unsupported raw TLS generation order %q", generation.Order)
		}
		p.PerConnection = &PerConnection{ShufflesExtensions: generation.Order == "moving", ECHPayloadLengths: append([]uint16{}, generation.ECH...)}
	}
	hadCache := p.Behavior.Has("quic.session_cache")
	group := m.Independent.Behavior
	if p.Behavior.Flag("quic.enabled") {
		group = m.Adapter.Behavior
	}
	for key, value := range group {
		if !p.Behavior.Has(key) {
			p.Behavior[key] = append(json.RawMessage(nil), value...)
		}
	}
	if p.Behavior.Flag("quic.enabled") {
		for _, copy := range m.Adapter.Copies {
			if !p.Behavior.Has(copy.To) {
				if !p.Behavior.Has(copy.From) {
					return fmt.Errorf("QUIC migration requires source policy %s", copy.From)
				}
				p.Behavior[copy.To] = append(json.RawMessage(nil), p.Behavior[copy.From]...)
			}
		}
	}
	for _, choice := range []struct{ key, source, present, absent string }{
		{"quic.ack_gap_policy", "quic.ack_gap_packets", m.ACK.Gap.Present, m.ACK.Gap.Absent},
		{"quic.ack_decimation", "quic.ack_decimation_after", m.ACK.Decimation.Present, m.ACK.Decimation.Absent},
	} {
		if !p.Behavior.Has(choice.key) {
			value := choice.absent
			if p.Behavior.Has(choice.source) {
				value = choice.present
			}
			p.Behavior[choice.key], _ = json.Marshal(value)
		}
	}
	if !p.Behavior.Has("quic.session_cache") {
		p.Behavior["quic.session_cache"] = json.RawMessage("false")
	}
	if p.Behavior.Text("quic.tls_source") == "independent" && p.QUICTLSSpec == nil {
		if p.Behavior.Flag("quic.session_cache") {
			p.QUICTLSSpec = m.Independent.Cached.clone()
		} else {
			p.QUICTLSSpec = m.Independent.Spec.clone()
		}
	}
	if !hadCache {
		spec, err := p.Spec()
		if err != nil {
			return err
		}
		cached := false
		for _, e := range spec.Extensions {
			if _, ok := e.(*tls.UtlsPreSharedKeyExtension); ok {
				cached = true
			}
		}
		p.Behavior["quic.session_cache"], _ = json.Marshal(cached)
		if cached && p.Behavior.Text("quic.tls_source") == "independent" {
			p.QUICTLSSpec = m.Independent.Cached.clone()
		}
	}
	if said() != before {
		p.Notes += "\nQUIC migration candidate: " + m.Provenance
	}
	return nil
}
