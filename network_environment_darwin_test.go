package tlsforge

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"unsafe"
)

// The fixture supplies typed CF values at the OS boundary. Native controls
// separately read the real SystemConfiguration store; no native result is mocked.
type networkCFStore struct {
	api      *darwinConfiguration
	values   map[uintptr]any
	store    map[string]uintptr
	next     uintptr
	released map[uintptr]int
}

func newNetworkCFStore() *networkCFStore {
	s := &networkCFStore{values: map[uintptr]any{}, store: map[string]uintptr{}, released: map[uintptr]int{}}
	s.api = &darwinConfiguration{
		newString: func(_ uintptr, value string, _ uint32) uintptr {
			if value == "allocation-failure" {
				return 0
			}
			return s.ref(value)
		},
		copyValue:       func(_, key uintptr) uintptr { return s.store[s.values[key].(string)] },
		release:         func(ref uintptr) { s.released[ref]++ },
		dictionaryValue: func(dict, key uintptr) uintptr { return s.values[dict].(map[string]uintptr)[s.values[key].(string)] },
		typeID: func(ref uintptr) uintptr {
			switch s.values[ref].(type) {
			case string:
				return 1
			case map[string]uintptr:
				return 2
			}
			return 3
		},
		stringTypeID: func() uintptr { return 1 }, dictionaryTypeID: func() uintptr { return 2 },
		stringBytes: func(ref uintptr, out *byte, length int64, _ uint32) bool {
			value := s.values[ref].(string)
			if value == "conversion-failure" {
				return false
			}
			b := unsafe.Slice(out, int(length))
			copy(b, value)
			if value != "missing-terminator" {
				b[len(value)] = 0
			} else {
				for i := range b {
					b[i] = 'x'
				}
			}
			return true
		},
	}
	return s
}
func (s *networkCFStore) ref(v any) uintptr { s.next++; s.values[s.next] = v; return s.next }
func (s *networkCFStore) dictionary(path string, fields map[string]string) {
	v := map[string]uintptr{}
	for k, text := range fields {
		v[k] = s.ref(text)
	}
	s.store[path] = s.ref(v)
}

func TestNetworkDarwinBindingRejectsMissingLibrariesAndSymbols(t *testing.T) {
	failure := errors.New("unavailable OS API")
	for fail := 1; fail <= 3; fail++ {
		opens, symbols, registered := 0, 0, 0
		api, e := bindDarwinConfiguration(func(string, int) (uintptr, error) {
			opens++
			if opens == fail {
				return 0, failure
			}
			return uintptr(opens), nil
		}, func(uintptr, string) (uintptr, error) { symbols++; return 0, failure }, func(any, uintptr) { registered++ })
		if api != nil || !errors.Is(e, failure) || registered != 0 {
			t.Fatal(fail, api, e, registered)
		}
		if fail <= 2 && symbols != 0 {
			t.Fatal("symbol lookup preceded library availability")
		}
	}
	s := newNetworkCFStore()
	s.store["bad"] = s.ref("not a dictionary")
	if s.api.dictionary("allocation-failure") != 0 || s.api.dictionary("bad") != 0 {
		t.Fatal("invalid CF dictionary accepted")
	}
	if s.released[s.store["bad"]] != 1 {
		t.Fatal("wrong-typed owned CF value leaked")
	}
	s.dictionary("valid", map[string]string{"valid": "en0", "conversion": "conversion-failure", "unterminated": "missing-terminator"})
	dict := s.api.dictionary("valid")
	if s.api.field(dict, "valid") != "en0" {
		t.Fatal("valid CFString lost")
	}
	for _, name := range []string{"allocation-failure", "missing", "conversion", "unterminated"} {
		if s.api.field(dict, name) != "" {
			t.Fatal("invalid CFString accepted", name)
		}
	}
	wrong := s.ref(42)
	s.values[dict].(map[string]uintptr)["wrong"] = wrong
	if s.api.field(dict, "wrong") != "" {
		t.Fatal("wrong CF type accepted")
	}
}

func TestNetworkDarwinRouteReadsPreferredFamilyAndObservedInterfaceType(t *testing.T) {
	failure := errors.New("interface unavailable")
	if _, e := darwinNetworkRoute([]string{"ipv4"}, func() (*darwinConfiguration, error) { return nil, failure }, net.InterfaceByName); !errors.Is(e, failure) {
		t.Fatal(e)
	}
	for _, kind := range []string{"IEEE80211", "Ethernet", "Other"} {
		s := newNetworkCFStore()
		s.dictionary("State:/Network/Global/IPv4", map[string]string{})
		s.dictionary("State:/Network/Global/IPv6", map[string]string{"PrimaryInterface": "owned0", "PrimaryService": "service", "Router": "2001:db8::1"})
		s.dictionary("Setup:/Network/Service/service/Interface", map[string]string{"Type": kind})
		loader := func() (*darwinConfiguration, error) { return s.api, nil }
		route, e := darwinNetworkRoute([]string{"ipv4", "ipv6"}, loader, func(name string) (*net.Interface, error) {
			if name != "owned0" {
				return nil, fmt.Errorf("unexpected interface %s", name)
			}
			return &net.Interface{Index: 7}, nil
		})
		want := map[string]string{"IEEE80211": "wifi", "Ethernet": "ethernet", "Other": "unknown"}[kind]
		if e != nil || route.index != 7 || route.kind != want || route.gateway != "2001:db8::1" {
			t.Fatal(route, e, want)
		}
		if _, e = darwinNetworkRoute([]string{"ipv6"}, loader, func(string) (*net.Interface, error) { return nil, failure }); !errors.Is(e, failure) {
			t.Fatal(e)
		}
	}
	s := newNetworkCFStore()
	loader := func() (*darwinConfiguration, error) { return s.api, nil }
	if _, e := darwinNetworkRoute([]string{"ipv4", "ipv6"}, loader, net.InterfaceByName); e == nil {
		t.Fatal("missing routes accepted")
	}
	for _, service := range []string{"", "unsafe/path", "unavailable"} {
		s.dictionary("State:/Network/Global/IPv4", map[string]string{"PrimaryInterface": "owned0", "PrimaryService": service})
		route, e := darwinNetworkRoute([]string{"ipv4"}, loader, func(string) (*net.Interface, error) { return &net.Interface{Index: 7}, nil })
		if e != nil || route.kind != "unknown" {
			t.Fatal("missing type invented", route, e)
		}
	}
	// No fixture operation exposes a MAC/SSID or a ready-made RTT estimate.
	for path := range s.store {
		if strings.Contains(path, "SSID") {
			t.Fatal(path)
		}
	}
}
