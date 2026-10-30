package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"github.com/Sec-CH-Lemon/tls-forge/echo"
	"github.com/Sec-CH-Lemon/tls-forge/fingerprint"
	"github.com/Sec-CH-Lemon/tls-forge/internal/atomicfile"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

func runCapture(ctx context.Context, args []string, out, errOut *printer) error {
	fs := newFlagSet("capture", out)
	browserName := fs.StringP("browser", "b", "",
		"browser to measure: chrome, chromium, edge, brave, or a path")
	headless := fs.Bool("headless", false, "run the browser without a window")
	save := fs.StringP("save", "s", "",
		"write a reusable profile here; a directory gets <name>/<platform>.json")
	install := fs.Bool("install", false,
		"keep the profile in this machine's own directory, where --profile finds it by name")
	name := fs.StringP("name", "n", "", "profile name (default: browser version; manual_ prefix with --manual)")
	asJSON := fs.BoolP("json", "j", false, "print the raw capture instead of a summary")
	timeout := fs.DurationP("timeout", "t", 2*time.Minute,
		"how long to wait for the browser; with --manual, ten minutes unless given")
	browserArgs := browserArgFlag(fs)
	visits := addVisitFlags(fs)
	policyFrom := fs.String("policy-from", "", "full profile or file whose unmeasured policies the capture inherits (default: newest shipped same family/platform)")
	provenanceDir := fs.String("provenance-dir", "", "directory for separate provenance JSON (default: provenance subtree, never a profile file)")
	sets := fs.StringArray("set", nil,
		"with --save or --install, a value the profile keeps of this machine, NAME=VALUE as its header carries it; "+
			"again for more")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := requireNoArgs(fs); err != nil {
		return err
	}
	if err := visits.check(fs); err != nil {
		return err
	}
	if *name != "" && !profile.ValidName(*name) {
		return fmt.Errorf("%w: invalid profile name %q", errUsage, *name)
	}
	if (*policyFrom != "" || *provenanceDir != "") && *save == "" && !*install {
		return fmt.Errorf("%w: --policy-from and --provenance-dir require --save or --install", errUsage)
	}
	if *policyFrom != "" {
		// Registry.Get validates every file/embedded/catalogue path.
		if _, err := profile.Get(*policyFrom); err != nil {
			return err
		}
	}
	settings, err := settingsOf(*sets)
	if err != nil {
		return err
	}
	if len(settings) > 0 && *save == "" && !*install {
		return fmt.Errorf("%w: --set changes the profile kept: give --save or --install", errUsage)
	}
	if *visits.manual && (*save != "" || *install) {
		if err := visits.namedHost(); err != nil {
			return err
		}
	}
	if *headless && *install && *name == "" {
		return fmt.Errorf("%w: --headless with --install: %s", errUsage, headlessKept)
	}

	// To stderr: --json makes standard output a document, and a line of
	// commentary in front of it is a document that will not parse.
	var measured *capture.Capture
	if *visits.manual {
		measured, err = measureVisitor(ctx, visits, visits.waitFor(fs, *timeout), errOut)
	} else {
		errOut.println("opening a browser… (it will show the result; you can close it)")
		measured, err = tlsforge.MeasureBrowser(ctx, tlsforge.MeasureOptions{
			Browser:     *browserName,
			Headless:    *headless,
			Timeout:     *timeout,
			BrowserArgs: *browserArgs,
		})
	}
	if err != nil {
		return err
	}

	profileOut := out
	if *asJSON {
		if err := printJSON(out, measured); err != nil {
			return err
		}
		if *save == "" && !*install {
			return nil
		}
		profileOut = errOut
	} else {
		printCapture(out, measured)
	}

	where := *save
	if *install {
		where = profile.DefaultDir()
		if where == "" {
			return fmt.Errorf("capture: nowhere to keep profiles; set TLSFORGE_PROFILES")
		}
		if err := os.MkdirAll(where, 0o755); err != nil {
			return fmt.Errorf("capture: %w", err)
		}
	}

	if where == "" {
		if namesNoServer(measured) {
			out.println("\nThe browser named no server, as at an address: capture at a name to keep a profile.")
			return nil
		}
		out.println("\nRe-run with --install to keep this profile, or --save <path> to write it out.")
		return nil
	}

	// --install means "the browser on this machine", and that is one thing
	// rather than one per version: measuring again after Chrome updates should
	// replace it, not leave two. --save is the other case — a profile going
	// somewhere to be kept or shipped — and that one is named for the browser.
	// --install keeps this machine's own browser as "local"; a browser a person
	// opened is kept under manual_<browser>_<version>. Visitor data must never
	// change local or a default browser-family alias; --name is an owner choice.
	profileName := *name
	if profileName == "" {
		profileName = profileNameFor(measured)
		if *install && !*visits.manual {
			profileName = localName
		} else if *visits.manual {
			profileName = "manual_" + profileName
		}
	}
	if profileName == localName && *name == "" && strings.Contains(measured.UserAgent(), headlessBrand) {
		return fmt.Errorf("capture: the browser measured was headless: %s; nothing was kept", headlessKept)
	}
	// One kept under the name of a profile tls-forge ships would answer for it
	// from then on, the directory being read first: only when asked by name.
	mode := "headed"
	if *headless {
		mode = "headless"
	}
	for _, arg := range *browserArgs {
		if strings.HasPrefix(arg, "--headless") {
			mode = "headless (--browser-arg)"
		}
	}
	if *visits.manual {
		mode = "manual; visitor-reported identity is not authenticated"
	}
	saved, path, err := saveProfile(where, profileName, measured, !*install || *name != "", settings, *policyFrom, *provenanceDir, mode)
	if err != nil {
		return err
	}
	profileOut.printf("\nwrote profile %q to %s\n", saved.Name, path)
	profileOut.printf("%s\n", saved.Notes)
	profileOut.printf("provenance: %s\n", captureProvenancePath(where, path, saved, *provenanceDir))
	if kept := machineValues(saved); len(kept) > 0 {
		profileOut.println("machine/persona values kept in this profile (--set NAME=VALUE changes one; hints require origin opt-in):")
		for _, field := range kept {
			profileOut.printf("  %-28s %s\n", field[0], field[1])
		}
	}
	if *install {
		profileOut.printf("use it with:  tls-forge fetch --profile %s <url>\n", shellQuote(saved.Name))
	}
	return nil
}

// headlessBrand is what a headless Chrome says in its user agent where a
// Chrome with a window says Chrome, and the one thing that sets the two apart
// in what they send: compare measured Chrome 155 headless against its headed
// profile alike but for it.
const headlessBrand = "HeadlessChrome"

// headlessKept is why a headless capture is not kept as local.
const headlessKept = "a headless Chrome names itself HeadlessChrome in its user agent, and --install keeps " +
	"the profile every command wears by default (local); capture with a window, or keep it under a name of its " +
	"own with --name, or as a file with --save"

// browserArgFlag registers --browser-arg on the two commands that drive a
// browser.
//
// Long-only and repeatable, like the other flags that get written once in a
// script and never typed: a letter for this would be a letter nobody remembers.
//
// It exists for the machine, not for the measurement. A CI runner needs
// `--no-sandbox` — Ubuntu 24.04 restricts the unprivileged user namespaces
// Chrome's sandbox is built on, and a Windows runner denies the sandbox access
// to the executable in its own tool cache — and without it Chrome starts, never
// loads the page, and the capture times out having watched a browser that was
// never going to answer.
func browserArgFlag(fs *pflag.FlagSet) *[]string {
	return fs.StringArray("browser-arg", nil,
		"extra flag for the browser, repeatable; for the machine, not the measurement")
}

// Seams for filesystem errors and invalid future platform mappings; the
// directory can disappear between Stat and OpenRoot.
var (
	capturedFilePath = profile.FilePath
	openProfileRoot  = os.OpenRoot
)

// saveProfile turns a measurement into a profile and returns the name it was
// filed under and the file it went to.
//
// Given a directory, the file is named after the profile, which is also the name
// --profile will find it by. Naming a captured Chrome 151 anything other than
// chrome_151 is how a machine ends up with a profile nobody can guess the name
// of.
func saveProfile(where, name string, measured *capture.Capture, mayShadow bool,
	settings []setting, policyOptions ...string) (saved *profile.Profile, path string, err error) {
	if !profile.ValidName(name) {
		return nil, "", fmt.Errorf("capture: invalid profile name %q", name)
	}
	policyFrom, provenanceDir := "", ""
	if len(policyOptions) > 0 {
		policyFrom = policyOptions[0]
	}
	if len(policyOptions) > 1 {
		provenanceDir = policyOptions[1]
	}
	basis, err := capturePolicyBasis(measured, policyFrom)
	if err != nil {
		return nil, "", err
	}
	built, err := profile.FromCapture(name, measured, basis)
	if err != nil {
		return nil, "", err
	}
	if err := applySettings(built, settings); err != nil {
		return nil, "", err
	}
	built.Notes = fmt.Sprintf("captured %s from %s; policy basis: %s (unmeasured policies inherited)", now().UTC().Format(time.RFC3339), built.UserAgent, basis.Name)
	// What the measurement saw that a profile cannot say, said beside it.
	if drawn, _ := profile.DrawnOf(measured); drawn != nil && len(drawn.Sometimes) > 0 {
		built.Notes += "; not in every hello: " + extensionsNamed(drawn.Sometimes)
	}
	if r, err := profile.ResumptionOf(measured); err == nil && r.Measured && !r.AsTLSForge() {
		built.Notes += "; resumed " + resumptionSaid(r, nil)
	}

	path = where
	var tree *os.Root
	var relative string
	if info, err := os.Stat(where); err == nil && info.IsDir() {
		// A directory per version holding one file per platform, so a machine
		// that measures Chrome 151 on two of them has one profile with two
		// spellings rather than two profiles. The platform is the one the name
		// says, else the one the browser does, which for a phone is not this
		// machine's, else this machine's.
		version, platform := profile.Split(built.Name)
		if platform == "" {
			platform = platformFrom(built.UserAgent)
		}
		if platform == "" {
			platform = profile.HostPlatform()
		}
		if !mayShadow && profile.Ships(version+"_"+platform) {
			return nil, "", fmt.Errorf("capture: %s_%s is a profile tls-forge ships, and one kept under its name "+
				"would answer for it from now on: give this one a name of its own with --name, or write it out "+
				"with --save", version, platform)
		}
		relative, err = capturedFilePath(version, platform)
		if err != nil {
			return nil, "", err
		}
		tree, err = openProfileRoot(where)
		if err != nil {
			return nil, "", err
		}
		defer func() { _ = tree.Close() }()
		if err := tree.MkdirAll(filepath.Dir(relative), 0o755); err != nil {
			return nil, "", err
		}
		built.Name = version + "_" + platform
		path = filepath.Join(where, filepath.FromSlash(relative))
	}

	if err := built.Validate(); err != nil {
		return nil, "", err
	}
	mode := "unknown; direct saveProfile caller"
	if len(policyOptions) > 2 {
		mode = policyOptions[2]
	}
	provenance, err := profile.ProvenanceForCapture(built, basis, measured, mode)
	if err != nil {
		return nil, "", err
	}
	for _, setting := range settings {
		if setting.name == "accept-language" {
			provenance.Fields["headers.accept-language"] = profile.FieldOrigin{Class: "user-provided", Source: "explicit --set"}
			continue
		}
		for _, field := range built.ClientHints {
			if machineFieldGroup(field.Name) == machineFieldGroup(setting.name) {
				provenance.Fields["client_hints."+field.Name] = profile.FieldOrigin{Class: "user-provided", Source: "explicit --set"}
			}
		}
	}
	// ProvenanceForCapture has serialized all raw JSON and cloned its source.
	// The only edits above add ordinary string origins, so encoding cannot fail.
	metadata, _ := json.MarshalIndent(provenance, "", "  ")
	metadata = append(metadata, '\n')
	metadataRoot, relativeMetadata := captureProvenanceDestination(where, path, built, provenanceDir)
	// Only an explicitly requested metadata directory is created here. A
	// file save still requires its original parent; metadata must not make an
	// otherwise unwritable profile destination silently become writable.
	if provenanceDir != "" {
		if err := os.MkdirAll(metadataRoot, 0o755); err != nil {
			return nil, "", err
		}
	}
	root, err := openProfileRoot(metadataRoot)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = root.Close() }()
	if err := root.MkdirAll(filepath.Dir(relativeMetadata), 0o755); err != nil {
		return nil, "", err
	}
	data, err := built.Save()
	if err == nil {
		if tree != nil {
			err = atomicfile.WriteRoot(tree, relative, data, 0o644)
		} else {
			err = atomicfile.Write(path, data, 0o644)
		}
	}
	if err != nil {
		return nil, "", err
	}
	if err := atomicfile.WriteRoot(root, relativeMetadata, metadata, 0o644); err != nil {
		return nil, "", err
	}
	return built, path, nil
}

// mark is the star against a profile kept on this machine.
func mark(local bool) string {
	if local {
		return "*"
	}
	return " "
}

// line is one row of the listing, with no trailing space on the rows that carry
// no arrow.
func line(mark, name string, fallback bool) string {
	row := mark + " " + name
	if fallback {
		row += strings.Repeat(" ", max(1, 30-len(row))) + "<"
	}
	return row
}

// now is time.Now, named so a test can produce a byte-identical profile.
var now = time.Now

// namesNoServer reports a capture whose ClientHello names no server, as a
// browser's at an address: no profile is made of it (profile.FromCapture).
func namesNoServer(c *capture.Capture) bool {
	hello, err := c.Hello()
	if err != nil {
		return false
	}
	_, named := hello.Extension(fingerprint.ExtServerName)
	return !named
}

// profileNameFor derives a stable name from what a browser says it is, e.g.
// "chrome_151": the brand a Chromium browser names, else its user agent.
//
// The name matters more than it looks: a profile called "chrome" that was
// measured from Chrome 151 reads as current forever, and the mismatch between
// the name and the handshake is invisible in every log it appears in.
func profileNameFor(c *capture.Capture) string {
	family, major := capturedBrowser(c)
	switch {
	case family == "":
		return "captured"
	case major == "":
		return family
	}
	return family + "_" + major
}

// platformFrom reads the platform a user agent says it runs on, spelled as a
// profile file is named, or nothing for one it does not say. The phones first:
// an iPhone says it is "like Mac OS X", and Android says it is Linux.
func platformFrom(userAgent string) string {
	for _, known := range []struct{ token, platform string }{
		{"Android", "android"},
		{"iPhone", "ios"},
		{"iPad", "ios"},
		{"iPod", "ios"},
		{"Windows", "windows"},
		{"Macintosh", "macos"},
		{"Linux", "linux"},
	} {
		if strings.Contains(userAgent, known.token) {
			return known.platform
		}
	}
	return ""
}

// brandNames are the brands Chromium browsers name themselves by, in
// navigator.userAgentData and sec-ch-ua. Brave's user agent is Chrome's word
// for word: the brands alone tell it apart.
var brandNames = map[string]string{
	"Google Chrome":    "chrome",
	"Microsoft Edge":   "edge",
	"Brave":            "brave",
	"Opera":            "opera",
	"YaBrowser":        "yandex",
	"Samsung Internet": "samsung",
}

// capturedBrowser reads the browser and its major version from the brands only a
// Chromium browser names: one it is known by, else chromium for one that
// names no brand of its own but Chromium's; else, as a browser without
// brands, from its user agent.
func capturedBrowser(c *capture.Capture) (family, major string) {
	chromium := ""
	if c.Navigator != nil {
		for _, b := range c.Navigator.Brands {
			if name, ok := brandNames[b.Brand]; ok {
				return name, safeBrowserMajor(b.Version)
			}
			if b.Brand == "Chromium" {
				chromium = safeBrowserMajor(b.Version)
			}
		}
	}
	if chromium != "" {
		return "chromium", chromium
	}
	return browserFrom(c.UserAgent())
}

var browserMajorPattern = regexp.MustCompile(`^[0-9]{1,4}$`)

func safeBrowserMajor(major string) string {
	if browserMajorPattern.MatchString(major) {
		return major
	}
	return ""
}

// browserFrom reads the browser and its major version out of a user-agent,
// returning empty strings for one it does not know.
//
// Order matters. Every Chromium-based browser puts "Chrome/" in its user-agent,
// so the ones that add their own token have to be checked first or they all
// come out as chrome.
func browserFrom(userAgent string) (family, major string) {
	for _, known := range []struct{ token, name string }{
		{"Edg/", "edge"},
		{"EdgA/", "edge"},
		{"EdgiOS/", "edge"},
		{"OPR/", "opera"},
		{"SamsungBrowser/", "samsung"},
		{"YaBrowser/", "yandex"},
		// The iOS ones name themselves apart from what they run on, which is
		// Safari's engine, and a "Version/" that is Safari's.
		{"CriOS/", "chrome"},
		{"FxiOS/", "firefox"},
		{"Chrome/", "chrome"},
		{"Firefox/", "firefox"},
		{"Version/", "safari"},
	} {
		index := strings.Index(userAgent, known.token)
		if index < 0 {
			continue
		}
		major, _, _ = strings.Cut(userAgent[index+len(known.token):], ".")
		return known.name, safeBrowserMajor(major)
	}
	return "", ""
}

func runServe(ctx context.Context, args []string, out, errOut *printer) error {
	fs := newFlagSet("serve", out)
	addr := fs.StringP("addr", "a", "127.0.0.1:0", "listen address")
	host := fs.String("host", "localhost", "hostname used in the URL and certificate")
	// Long-only, like the other flags that are set once in a script and never
	// typed twice: a letter for each would be a letter nobody remembers.
	tickets := fs.Bool("session-tickets", false, "allow TLS session resumption")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := requireNoArgs(fs); err != nil {
		return err
	}

	server, err := echo.Start(echo.WithAddr(*addr), echo.WithHost(*host), echo.WithSessionTickets(*tickets))
	if err != nil {
		return err
	}
	defer func() { _ = server.Close() }()

	warnPublicListener("serve", server.Addr(), errOut)
	out.println(server.URL())
	out.println("  /          a page that measures the browser that opens it")
	out.println("  /api/all   this connection's fingerprint, as JSON")
	out.println()
	out.println("The certificate is self-signed and generated for this run, so clients")
	out.println("must be told to accept it (curl -k, tlsforge --insecure).")
	out.println("Ctrl-C to stop.")

	<-ctx.Done()
	return nil
}

func runProfiles(_ context.Context, args []string, out, _ *printer) error {
	fs := newFlagSet("profiles", out)
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := requireNoArgs(fs); err != nil {
		return err
	}

	// What a run lands on when nobody names a profile. Resolved rather than
	// printed as written, because "chrome" is two hops from a file and the
	// useful thing to know is which file. The same rule the commands use, or
	// the listing would point at a shipped profile while every run wore the
	// locally measured one.
	fallback := ""
	if p, err := profile.Get(defaultProfileName()); err == nil {
		fallback = p.Name
	}

	out.println("Measured from a real browser.")
	out.println("  * kept on this machine, and used ahead of anything shipped")
	out.println("  < what you get when no profile is named")
	out.println()

	measured := map[string]bool{}
	for _, group := range profile.Default.Measured() {
		p, err := profile.Get(group.Name)
		if err != nil {
			continue
		}
		measured[group.Name] = true
		// The mark goes on the file that is actually used, not on every name
		// that reaches it: a version and its platform both lead to one file, and
		// two arrows pointing at one thing say less than one.
		out.println(line(mark(group.Local), group.Name, len(group.Variants) == 0 &&
			p.Name == fallback))

		// Every line is a name that can be copied into --profile, rather than a
		// platform the reader has to work out how to spell.
		for _, variant := range group.Variants {
			full := group.Name + "_" + variant.Platform
			measured[full] = true
			out.println(line(mark(variant.Local)+"  ", full, full == fallback))
		}
	}

	// One lookup per name, and a name that cannot be resolved is listed with the
	// catalogue rather than silently dropped: a profile that exists but will not
	// load is exactly the thing a user needs to be told about.
	var catalogue []string
	for _, name := range profile.Names() {
		if measured[name] {
			continue
		}
		if p, err := profile.Get(name); err != nil || len(p.ClientHello) == 0 {
			catalogue = append(catalogue, name)
		}
	}

	out.println()
	out.println("From the tls-client catalogue, a handshake but no headers of its own:")
	out.println()
	for i, name := range catalogue {
		out.printf("  %-24s", name)
		if i%3 == 2 {
			out.println()
		}
	}
	out.println()
	out.println()
	out.println("Measure your own with:  tls-forge capture --install")
	if dir := profile.DefaultDir(); dir != "" {
		out.printf("Kept on this machine in: %s\n", dir)
	}
	return nil
}

func printJSON(out io.Writer, v any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(v)
}
