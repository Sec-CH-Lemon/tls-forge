package profile

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/bogdanfinn/tls-client/profiles"
)

// Profiles measured against a real browser and committed. Each one was produced
// by `tls-forge capture --save` and can be reproduced by running it again.
//
//go:embed all:data
var embedded embed.FS

// Registry resolves a profile name.
//
// Four sources, in order: profiles registered at runtime, profiles kept in this
// machine's own directory, profiles measured and committed here, and the
// tls-client catalogue. The order matters: someone who captures their own
// Chrome and keeps it under "chrome_151" should get theirs, not the one that
// shipped, because theirs is the browser a server will be comparing against.
type Registry struct {
	mu    sync.RWMutex
	added map[string]*Profile
	dir   string
}

// NewRegistry returns a registry over the built-in sources and this machine's
// own profile directory.
func NewRegistry() *Registry {
	return &Registry{added: map[string]*Profile{}, dir: DefaultDir()}
}

// DefaultDir is where profiles measured on this machine are kept.
//
// Under the user's config directory rather than beside the binary, because a
// profile is this machine's measurement of this machine's browser: it does not
// belong to an install that a package manager may replace, and it should
// survive one.
//
// TLSFORGE_PROFILES moves it, which is how a run in a container or a test says
// where to look without touching a real one.
func DefaultDir() string {
	if dir := os.Getenv("TLSFORGE_PROFILES"); dir != "" {
		return dir
	}
	base, err := os.UserConfigDir()
	if err != nil {
		// No home to speak of, which happens in a container with no HOME set.
		// The other three sources still answer.
		return ""
	}
	return filepath.Join(base, "tls-forge", "profiles")
}

// Dir is where this registry looks for profiles kept on this machine.
func (r *Registry) Dir() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.dir
}

// SetDir points the registry at another directory.
func (r *Registry) SetDir(dir string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dir = dir
}

// hostPlatform is what this machine is, spelled the way a profile file is
// named. A variable so a test can be somewhere else.
var hostPlatform = platformName(runtime.GOOS)

func platformName(goos string) string {
	switch goos {
	case "darwin":
		return "macos"
	case "windows":
		return "windows"
	default:
		return goos
	}
}

// lookup finds a profile in a tree laid out as either a flat `<name>.json` or a
// directory per version holding one file per platform.
//
// Three ways a name can arrive, and all three answer:
//
//	chrome_151          a version, which means this machine's platform
//	chrome_151_macos    a version and a platform, said outright
//	chrome_151          a flat file, which is what a hand-written one looks like
//
// The platform default is the host's because that is what the plain name means:
// Chrome 151 as it looks from here. Anything else is one word longer and says
// so, which is the right way round for a thing that changes what a server sees.
func lookup(fsys fs.FS, root, name string) (data []byte, at string, ok bool) {
	at = path.Join(root, name+".json")
	if data, err := fs.ReadFile(fsys, at); err == nil {
		return data, at, true
	}

	// A version on its own: this machine's platform, or whichever there is.
	if entries, err := fs.ReadDir(fsys, path.Join(root, name)); err == nil {
		var files []string
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
				files = append(files, entry.Name())
			}
		}
		sort.Strings(files)
		wanted := hostPlatform + ".json"
		for _, file := range files {
			if file == wanted {
				at = path.Join(root, name, file)
				if data, err := fs.ReadFile(fsys, at); err == nil {
					return data, at, true
				}
			}
		}
		// No capture for this machine's platform, so any of them will do.
		//
		// Falling back rather than failing, because the platform is not what a
		// version name promises and not what the fingerprint is made of.
		// Measured: Chrome 151 sends the same ClientHello on macOS and on Linux,
		// down to the byte — it carries its own BoringSSL. What differs is the
		// user-agent and sec-ch-ua-platform, and a profile saying macOS is a
		// coherent identity from anywhere; it is what `--profile chrome_151_macos`
		// has always meant. Refusing instead made `chrome_151` resolve to nothing
		// on Windows, where no capture exists yet, and took the default profile
		// down with it: the library would not start at all on a platform this
		// project ships a binary for. Sorted, so which one it lands on does not
		// depend on the order a filesystem happened to hand them over.
		if len(files) > 0 {
			at = path.Join(root, name, files[0])
			if data, err := fs.ReadFile(fsys, at); err == nil {
				return data, at, true
			}
		}
		return nil, "", false
	}

	// A version and a platform: the last word is the platform.
	if cut := strings.LastIndex(name, "_"); cut > 0 {
		at = path.Join(root, name[:cut], name[cut+1:]+".json")
		if data, err := fs.ReadFile(fsys, at); err == nil {
			return data, at, true
		}
	}
	return nil, "", false
}

// namesIn lists every name a tree answers to.
//
// A version directory answers to two kinds of name: its own, which means this
// machine's platform, and one per platform inside it. Both are listed, because
// both resolve, and because a version name is what a family name looks for:
// "chrome" means the newest chrome_<major>, and it cannot find one that is
// never named.
func namesIn(fsys fs.FS, root string) []string {
	entries, err := fs.ReadDir(fsys, root)
	if err != nil {
		return nil
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() {
			if strings.HasSuffix(entry.Name(), ".json") {
				names = append(names, strings.TrimSuffix(entry.Name(), ".json"))
			}
			continue
		}
		inner, err := fs.ReadDir(fsys, path.Join(root, entry.Name()))
		if err != nil {
			continue
		}
		var platforms []string
		for _, file := range inner {
			if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
				continue
			}
			platforms = append(platforms, entry.Name()+"_"+strings.TrimSuffix(file.Name(), ".json"))
		}
		if len(platforms) > 0 {
			names = append(names, entry.Name())
			names = append(names, platforms...)
		}
	}
	return names
}

// HostPlatform is this machine, spelled the way a profile file is named.
func HostPlatform() string { return hostPlatform }

// Split separates a name into the version and the platform it names, if it
// names one. Only a platform this project knows counts: "chrome_151" is a
// version whose last word happens to be a number, not a platform called 151.
func Split(name string) (version, platform string) {
	for _, known := range []string{"macos", "linux", "windows"} {
		if rest, ok := strings.CutSuffix(name, "_"+known); ok {
			return rest, known
		}
	}
	return name, ""
}

// fromDir reads a profile out of this machine's directory.
func (r *Registry) fromDir(name string) (*Profile, bool) {
	dir := r.Dir()
	// A name is a file name here, so one carrying a separator would reach
	// outside the directory it is supposed to name.
	if dir == "" || name != filepath.Base(name) || name == "." || name == ".." {
		return nil, false
	}
	data, at, ok := lookup(os.DirFS(dir), ".", name)
	if !ok {
		return nil, false
	}
	p, err := Load(data)
	if err != nil {
		return nil, false
	}
	p.source = filepath.Join(dir, filepath.FromSlash(at))
	return p, true
}

// dirNames lists what is in this machine's directory.
func (r *Registry) dirNames() []string {
	dir := r.Dir()
	if dir == "" {
		return nil
	}
	return namesIn(os.DirFS(dir), ".")
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
	r.added[p.Name] = p.Clone()
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
		return p.Clone(), nil
	}

	// A path rather than a name: the file said, taken as given. Someone with a
	// profile in hand should not have to move it anywhere first.
	if looksLikePath(name) {
		data, err := os.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("profile: %w", err)
		}
		p, err := Load(data)
		if err == nil {
			p.source = name
		}
		return p, err
	}

	if p, ok := r.fromDir(name); ok {
		return p, nil
	}

	if data, _, ok := lookup(embedded, "data", name); ok {
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

// looksLikePath tells a file from a name. A profile is named without a suffix
// and without a separator, so either of those means a file was meant.
func looksLikePath(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".json") ||
		strings.ContainsRune(name, filepath.Separator) ||
		strings.ContainsRune(name, '/')
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
		measured := r.HasHandshake(name)
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

// KeptHere lists the profiles in this machine's own directory, which are the
// ones that win over anything shipped.
func (r *Registry) KeptHere() []string { return r.dirNames() }

// Variant is one platform a version was measured on.
type Variant struct {
	Platform string
	// Local says this one came from this machine's directory, which is the copy
	// that will be used.
	Local bool
}

// Group is one measured profile and the platforms it was measured on.
//
// A version measured on three platforms is one profile with three spellings
// rather than three profiles: the handshake is the same on all of them, and
// only the user-agent and the platform hint differ.
type Group struct {
	// Name is what to ask for to get this machine's platform.
	Name     string
	Variants []Variant
	// Local says this machine has something under this name, which is then the
	// copy that answers.
	Local bool
}

// groupsIn reads a tree's layout rather than guessing it from names: whether
// "chrome_151" is a version or a version and a platform is a fact about the
// files, not about where the underscores fall.
func groupsIn(fsys fs.FS, root string) map[string][]string {
	entries, err := fs.ReadDir(fsys, root)
	if err != nil {
		return nil
	}
	groups := map[string][]string{}
	for _, entry := range entries {
		if !entry.IsDir() {
			if name, ok := strings.CutSuffix(entry.Name(), ".json"); ok {
				groups[name] = nil
			}
			continue
		}
		inner, err := fs.ReadDir(fsys, path.Join(root, entry.Name()))
		if err != nil {
			continue
		}
		var platforms []string
		for _, file := range inner {
			if platform, ok := strings.CutSuffix(file.Name(), ".json"); ok && !file.IsDir() {
				platforms = append(platforms, platform)
			}
		}
		if len(platforms) > 0 {
			sort.Strings(platforms)
			groups[entry.Name()] = platforms
		}
	}
	return groups
}

// Measured lists the profiles taken from a real browser, grouped by version.
//
// Both sources at once, not one instead of the other: a machine that has
// measured Chrome 151 on its own platform still resolves the shipped profile
// for the others, and a listing that showed only the local one would be saying
// less than is true.
func (r *Registry) Measured() []Group {
	shipped := groupsIn(embedded, "data")
	local := map[string][]string{}
	if dir := r.Dir(); dir != "" {
		local = groupsIn(os.DirFS(dir), ".")
	}

	var names []string
	for name := range shipped {
		names = append(names, name)
	}
	for name := range local {
		if _, seen := shipped[name]; !seen {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	groups := make([]Group, 0, len(names))
	for _, name := range names {
		here, isLocal := local[name]
		group := Group{Name: name, Local: isLocal}

		platforms := append(append([]string{}, shipped[name]...), here...)
		sort.Strings(platforms)
		for _, platform := range slices.Compact(platforms) {
			group.Variants = append(group.Variants, Variant{
				Platform: platform,
				Local:    slices.Contains(here, platform),
			})
		}
		groups = append(groups, group)
	}
	return groups
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

	for _, name := range r.dirNames() {
		if !seen[name] {
			seen[name] = true
			measured = append(measured, name)
		}
	}

	for _, name := range namesIn(embedded, "data") {
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

// HasHandshake reports whether a name resolves to a profile built from a real
// captured ClientHello rather than to a catalogue entry. It is what lets a
// caller tell "this is my browser" from "this is close to some browser".
func (r *Registry) HasHandshake(name string) bool {
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
