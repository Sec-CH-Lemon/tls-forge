package profile

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/bogdanfinn/tls-client/profiles"
)

// Profiles measured against a real browser and committed. Each one was produced
// by `tls-forge capture -save` and can be reproduced by running it again.
//
//go:embed data/*.json
var embedded embed.FS

// Registry resolves a profile name.
//
// Three sources, in order: profiles registered at runtime, profiles measured and
// committed here, and the tls-client catalogue. The order matters — a caller who
// captures their own Chrome and registers it under "chrome" should get theirs,
// not ours.
type Registry struct {
	mu    sync.RWMutex
	added map[string]*Profile
}

// NewRegistry returns an empty registry over the built-in sources.
func NewRegistry() *Registry {
	return &Registry{added: map[string]*Profile{}}
}

// Default is the registry the package-level functions use.
var Default = NewRegistry()

// Register adds or replaces a profile.
func (r *Registry) Register(p *Profile) error {
	if p == nil || p.Name == "" {
		return fmt.Errorf("profile: cannot register a profile without a name")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.added[p.Name] = p
	return nil
}

// Get resolves a name to a profile.
func (r *Registry) Get(name string) (*Profile, error) {
	if name == "" {
		return nil, fmt.Errorf("profile: no name given")
	}

	r.mu.RLock()
	p, ok := r.added[name]
	r.mu.RUnlock()
	if ok {
		return p, nil
	}

	if data, err := embedded.ReadFile("data/" + name + ".json"); err == nil {
		return Load(data)
	}

	if _, ok := profiles.MappedTLSClients[name]; ok {
		// A bare reference to the catalogue. It carries a handshake and HTTP/2
		// settings but no headers — tls-client has never claimed to know what
		// headers a browser sends, only how it connects.
		return &Profile{Name: name, Base: name}, nil
	}

	// A family name means the newest measured member of that family, so
	// "chrome" keeps meaning the current Chrome after the next capture instead
	// of pinning whichever one happened to be current when the code was
	// written. The exact name is always available for pinning on purpose.
	if newest := r.newestInFamily(name); newest != "" {
		return r.Get(newest)
	}

	return nil, fmt.Errorf("profile: unknown profile %q (try one of: %s)",
		name, strings.Join(firstN(r.Names(), 8), ", "))
}

// newestInFamily finds the highest-numbered `<family>_<major>` profile,
// preferring measured ones.
//
// Preferring measured is not the same as preferring newest. A catalogue entry
// for a later Chrome still carries no headers of its own, so resolving "chrome"
// to it would trade a complete impersonation for a handshake-only one — and
// quietly, at the moment the catalogue happened to move ahead.
func (r *Registry) newestInFamily(family string) string {
	prefix := family + "_"
	best, bestMajor, bestMeasured := "", -1, false

	for _, name := range r.Names() {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		major, err := strconv.Atoi(name[len(prefix):])
		if err != nil {
			// A suffix that is not a version — "chrome_psk", say — is a distinct
			// profile, not a candidate for "the newest chrome".
			continue
		}
		measured := r.Measured(name)
		if measured != bestMeasured {
			if measured {
				best, bestMajor, bestMeasured = name, major, true
			}
			continue
		}
		if major > bestMajor {
			best, bestMajor = name, major
		}
	}
	return best
}

// Names lists every profile that can be resolved, measured ones first.
func (r *Registry) Names() []string {
	seen := map[string]bool{}
	var measured, stock []string

	r.mu.RLock()
	for name := range r.added {
		if !seen[name] {
			seen[name] = true
			measured = append(measured, name)
		}
	}
	r.mu.RUnlock()

	entries, _ := fs.Glob(embedded, "data/*.json")
	for _, entry := range entries {
		name := strings.TrimSuffix(path.Base(entry), ".json")
		if !seen[name] {
			seen[name] = true
			measured = append(measured, name)
		}
	}
	for name := range profiles.MappedTLSClients {
		if !seen[name] {
			seen[name] = true
			stock = append(stock, name)
		}
	}

	sort.Strings(measured)
	sort.Strings(stock)
	return append(measured, stock...)
}

// Measured reports whether a name resolves to a profile built from a real
// captured ClientHello rather than to a catalogue entry. It is what lets a
// caller tell "this is my browser" from "this is close to some browser".
func (r *Registry) Measured(name string) bool {
	p, err := r.Get(name)
	return err == nil && len(p.ClientHello) > 0
}

// Get resolves a name against the default registry.
func Get(name string) (*Profile, error) { return Default.Get(name) }

// Names lists the default registry's profiles.
func Names() []string { return Default.Names() }

// Register adds a profile to the default registry.
func Register(p *Profile) error { return Default.Register(p) }

func firstN(values []string, n int) []string {
	if len(values) <= n {
		return values
	}
	return append(values[:n:n], "…")
}
