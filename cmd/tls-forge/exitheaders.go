package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/net/http/httpguts"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge/v7"
	"github.com/Sec-CH-Lemon/tls-forge/v7/profile"
)

// The header fields a proxy says where its tunnel comes out in, and what to ask
// when it does not.
//
// exit-headers.json, built in, holds every field and probe known when it was
// written. The file --exit-headers names, wherever it is, is of the same shape
// and laid over it as mergeRight lays one object over another: it adds a
// field, replaces one of the same key, or takes one out with "off", and the
// next run reads it, without anything being built.

// builtInExitHeaders is exit-headers.json. A variable so a test can break it.
//
//go:embed exit-headers.json
var builtInExitHeaders []byte

// exitTable is such a file.
type exitTable struct {
	// About says what the file is, for whoever opens it.
	About  string      `json:"about,omitempty"`
	Fields []exitField `json:"fields"`
	// Probes are asked of a site when no field said where a request to it came
	// out, over the connection the request went out on.
	Probes []exitProbe `json:"probes,omitempty"`
}

// exitReading is how an address is read out of the answer to a question asked
// to learn it: Format is "json", an object, or "lines", a key=value to a line,
// and IP and Country the keys that hold the address and the country.
type exitReading struct {
	Format  string `json:"format"`
	IP      string `json:"ip"`
	Country string `json:"country,omitempty"`
}

// exitProbe is a question asked of the site a request went to, over the same
// connection, for the sites that answer where a visitor comes from.
type exitProbe struct {
	// When is the header field a response comes with when its site answers.
	When string `json:"when"`
	// Path is asked of the scheme, host and port the request ended at.
	Path string `json:"path"`
	exitReading
	Provider string `json:"provider,omitempty"`
	Source   string `json:"source,omitempty"`
	Note     string `json:"note,omitempty"`
	// Off takes out the probe of the same key in the file this one is laid
	// over, and is not asked itself.
	Off bool `json:"off,omitempty"`
}

// key is what a probe is known by when one file is laid over another: the
// field it waits for, in any case, and the path it asks.
func (p exitProbe) key() string {
	return strings.ToLower(p.When) + " " + p.Path
}

// exitResolve is how the name a proxy gave an exit is turned into its address:
// a question asked through the same proxy, with a user name that says to go
// out through the exit of that name.
type exitResolve struct {
	// User is the user name to ask with: {user} is the one the run was given,
	// {value} the name the proxy gave.
	User string `json:"user"`
	// URL is what is asked, and the rest how its answer is read.
	URL string `json:"url"`
	exitReading
}

// exitField is a header field in which a proxy's answer to CONNECT says where
// the tunnel comes out.
type exitField struct {
	// Header is the field's name, in any case.
	Header string `json:"header"`
	// Value is what it holds: "address", an IP address with or without a port
	// after it, "hash", the proxy's own hash of the address, "name", whatever
	// else the proxy calls where the tunnel comes out, or nothing, for an
	// address or a hash.
	Value string `json:"value,omitempty"`
	// Param is the parameter that holds it, when the field is parameters
	// rather than the value alone: name=value pairs separated by semicolons,
	// as brd_ip in Bright Data's Proxy-Status.
	Param string `json:"param,omitempty"`
	// In is where the field comes: "connect", the proxy's answer when it opens
	// the tunnel, which is what it means when it is left out, or "response",
	// the answer to the request, which a proxy that reads the traffic writes
	// it into. A site can write a field there as well, so one is believed only
	// when the answer to CONNECT said nothing.
	In string `json:"in,omitempty"`
	// Country is the field that names the tunnel's country beside it, when
	// there is one, and CountryParam the parameter of it that does, when the
	// field is parameters.
	Country      string `json:"country,omitempty"`
	CountryParam string `json:"country_param,omitempty"`
	// Ask is what the CONNECT has to say for the proxy to answer with the
	// field, for a proxy that says it only when asked. Every CONNECT says it,
	// to every proxy.
	Ask map[string]string `json:"ask,omitempty"`
	// Resolve is how a hash or a name in the field is turned into the address
	// it stands for, when the proxy says how.
	Resolve *exitResolve `json:"resolve,omitempty"`
	// Provider, Source and Note are for whoever reads the file: who sends it,
	// where that is written down, and anything else worth knowing.
	Provider string `json:"provider,omitempty"`
	Source   string `json:"source,omitempty"`
	Note     string `json:"note,omitempty"`
	// Off takes out the field of the same key in the file this one is laid
	// over, and is not read itself.
	Off bool `json:"off,omitempty"`
}

// key is what a field is known by when one file is laid over another: its
// name, in any case, the answer it comes in, and the parameter of it that is
// read, when one is, so that one field can be read for more than one
// parameter.
func (f exitField) key() string {
	key := strings.ToLower(f.Header) + " in " + either(f.In, "connect")
	if f.Param != "" {
		key += " param " + strings.ToLower(f.Param)
	}
	return key
}

// exitValues are what a field can say it holds, exitPlaces where it can say
// it comes, and exitFormats what an answer to a question can be.
var (
	exitValues  = []string{"", "address", "hash", "name"}
	exitPlaces  = []string{"", "connect", "response"}
	exitFormats = []string{"json", "lines"}
)

// usable says an answer can be read this way.
func (r exitReading) usable() bool {
	return slices.Contains(exitFormats, r.Format) && strings.TrimSpace(r.IP) != ""
}

// unaskable are the header fields a CONNECT cannot be made to say: those that
// frame the request, which the proxy would read as a body to wait for or as
// how to treat the connection, and the credentials, which come from the
// proxy's URL.
var unaskable = map[string]bool{
	"host": true, "content-length": true, "transfer-encoding": true, "connection": true,
	"keep-alive": true, "proxy-connection": true, "upgrade": true, "expect": true, "te": true,
	"trailer": true, "proxy-authorization": true,
}

// parseExitTable reads such a file, refusing one it cannot be sure it has read
// right: a key it does not know is a key misspelled, a name no header field
// can have is a name that would never be found, and a second field of the
// same key is one that would never be read.
func parseExitTable(data []byte, name string) (exitTable, error) {
	// What an editor that begins every file with a byte order mark saved.
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if len(bytes.TrimSpace(data)) == 0 {
		return exitTable{}, fmt.Errorf("fetch: %s: the file is empty", name)
	}
	var table exitTable
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&table); err != nil {
		return exitTable{}, fmt.Errorf("fetch: %s: %w", name, err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return exitTable{}, fmt.Errorf("fetch: %s: more after the table, which nothing would read", name)
	}
	fields := map[string]int{}
	for i, field := range table.Fields {
		if field.Off {
			// It says which field to take out, and nothing else of it is read.
			field = exitField{Header: field.Header, In: field.In, Param: field.Param}
		}
		if err := field.check(); err != "" {
			return exitTable{}, fmt.Errorf("fetch: %s: field %d %s", name, i+1, err)
		}
		if before, seen := fields[field.key()]; seen {
			return exitTable{}, fmt.Errorf("fetch: %s: field %d has the key of field %d, %s", name, i+1, before, field.key())
		}
		fields[field.key()] = i + 1
	}
	probes := map[string]int{}
	for i, probe := range table.Probes {
		if probe.Off {
			probe.exitReading = exitReading{Format: exitFormats[0], IP: "-"}
		}
		if !httpguts.ValidHeaderFieldName(probe.When) || !strings.HasPrefix(probe.Path, "/") || !probe.usable() {
			return exitTable{}, fmt.Errorf("fetch: %s: probe %d needs a field to come when, a path, "+
				"a format of json or lines, and the key of the address", name, i+1)
		}
		if before, seen := probes[probe.key()]; seen {
			return exitTable{}, fmt.Errorf("fetch: %s: probe %d has the key of probe %d, %s", name, i+1, before, probe.key())
		}
		probes[probe.key()] = i + 1
	}
	return table, nil
}

// check is what is wrong with a field, or nothing.
func (f exitField) check() string {
	switch {
	case !httpguts.ValidHeaderFieldName(f.Header):
		return fmt.Sprintf("needs a header, and %q is not the name of one", f.Header)
	case !slices.Contains(exitValues, f.Value) || !slices.Contains(exitPlaces, f.In):
		return "needs a value of address, hash, name or none, and to be in connect, response or nowhere said"
	case f.Country != "" && !httpguts.ValidHeaderFieldName(f.Country):
		return fmt.Sprintf("names its country in %q, which is not the name of a header field", f.Country)
	}
	for _, asked := range slices.Sorted(maps.Keys(f.Ask)) {
		if !httpguts.ValidHeaderFieldName(asked) || !httpguts.ValidHeaderFieldValue(f.Ask[asked]) ||
			unaskable[strings.ToLower(asked)] {
			return fmt.Sprintf("asks every CONNECT to say %q: %q, which a CONNECT cannot say", asked, f.Ask[asked])
		}
	}
	if how := f.Resolve; how != nil && (!strings.Contains(how.User, "{value}") || !webURL(how.URL) || !how.usable()) {
		return "resolves with a user that has {value} in it, an http or https URL, a format of json or lines, " +
			"and the key of the address"
	}
	return ""
}

// webURL says a URL is one that can be asked: http or https, of a host.
func webURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// mergeExitTables is over laid over base, as mergeRight lays one object over
// another: a field or a probe of over replaces base's of the same key, one
// that is "off" takes base's out, and the rest are added. over's are read
// first, then what is left of base's, each in their own order, so that where
// an answer holds a field of each, over's is the one believed.
func mergeExitTables(base, over exitTable) exitTable {
	return exitTable{
		About:  either(over.About, base.About),
		Fields: mergeByKey(base.Fields, over.Fields, exitField.key, func(f exitField) bool { return f.Off }),
		Probes: mergeByKey(base.Probes, over.Probes, exitProbe.key, func(p exitProbe) bool { return p.Off }),
	}
}

// mergeByKey is over's items that are not off, then base's that over has none
// of the key of.
func mergeByKey[T any](base, over []T, key func(T) string, off func(T) bool) []T {
	laid := map[string]bool{}
	var out []T
	for _, item := range over {
		laid[key(item)] = true
		if !off(item) {
			out = append(out, item)
		}
	}
	for _, item := range base {
		if !laid[key(item)] {
			out = append(out, item)
		}
	}
	return out
}

// loadExitTable is what a run reads: the table built in, with the file named
// laid over it when one is.
func loadExitTable(named string) (exitTable, error) {
	table, err := parseExitTable(builtInExitHeaders, "exit-headers.json, built in")
	if err != nil {
		return exitTable{}, err
	}
	if named == "" {
		return table, nil
	}
	data, err := os.ReadFile(named)
	if err != nil {
		return exitTable{}, fmt.Errorf("fetch: %w", err)
	}
	over, err := parseExitTable(data, named)
	if err != nil {
		return exitTable{}, err
	}
	return mergeExitTables(table, over), nil
}

// read is where an answer to a question asked to learn it says a request came
// out, or nothing when it does not say it as an address.
func (r exitReading) read(body []byte) egress {
	said := map[string]string{}
	if r.Format == "json" {
		var object map[string]any
		_ = json.Unmarshal(body, &object)
		for key, value := range object {
			if text, ok := value.(string); ok {
				said[key] = text
			}
		}
	} else {
		for _, line := range strings.Split(string(body), "\n") {
			key, value, _ := strings.Cut(strings.TrimSpace(line), "=")
			said[key] = value
		}
	}
	addr, ok := addressIn(strings.TrimSpace(said[r.IP]))
	if !ok {
		return egress{}
	}
	return egress{IP: addr.String(), Country: said[r.Country]}
}

// exitIn is where a proxy's answer says its tunnel comes out, or nothing when
// it does not say. Only the fields that come in that answer are read: in
// "connect" for the answer to CONNECT, in "response" for the answer to the
// request.
//
// An address, or a proxy's hash of one, has to be what it claims before it is
// believed: it is somebody else's text, and fetch prints it on a terminal,
// which escapes nothing. A hash is letters and digits and nothing else, at
// least sixteen of them, which is how no address is written.
func exitIn(answer tlsforge.Header, fields []exitField, in string) (egress, exitField) {
	for _, field := range fields {
		if either(field.In, "connect") != in {
			continue
		}
		value := strings.TrimSpace(answer.Get(field.Header))
		if field.Param != "" {
			value = paramIn(value, field.Param)
		}
		if found, ok := field.read(value); ok {
			found.Country = answer.Get(field.Country)
			if field.CountryParam != "" {
				found.Country = paramIn(found.Country, field.CountryParam)
			}
			return found, field
		}
	}
	return egress{}, exitField{}
}

// read is where a value says the tunnel comes out, when it holds what the
// field says it holds.
func (f exitField) read(value string) (egress, bool) {
	addr, isAddress := addressIn(value)
	switch {
	case f.Value == "name":
		return egress{Hash: value}, nameOfAnExit.MatchString(value)
	case isAddress && f.Value != "hash":
		return egress{IP: addr.String()}, true
	default:
		return egress{Hash: value}, f.Value != "address" && hashOfAnAddress.MatchString(value)
	}
}

// askedBy is what every CONNECT is to say for the proxies that answer only
// when asked, in the order of the fields' names. A name asked for more than
// once, in any case, is said once, as the first field to ask for it asks:
// the fields of a file laid over the table come first.
func askedBy(fields []exitField) tlsforge.Header {
	var asked tlsforge.Header
	said := map[string]bool{}
	for _, field := range fields {
		for _, name := range slices.Sorted(maps.Keys(field.Ask)) {
			if said[strings.ToLower(name)] {
				continue
			}
			said[strings.ToLower(name)] = true
			asked = append(asked, profile.Field{Name: name, Value: field.Ask[name]})
		}
	}
	slices.SortStableFunc(asked, func(a, b profile.Field) int { return strings.Compare(a.Name, b.Name) })
	return asked
}

// headerOf is a response's header fields as the fields of an answer, by name,
// because a map has no order to keep.
func headerOf(fields map[string][]string) tlsforge.Header {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	slices.Sort(names)
	var out tlsforge.Header
	for _, name := range names {
		for _, value := range fields[name] {
			out = append(out, profile.Field{Name: name, Value: value})
		}
	}
	return out
}

// paramIn is one parameter of a field made of them: name=value pairs separated
// by semicolons, the value in quotes or not, in any of the items of a list of
// them separated by commas, as a Proxy-Status that more than one proxy wrote
// is. A semicolon or a comma in quotes separates nothing, so that a parameter
// written inside another's value is not taken for one. Nothing when there is
// no such parameter.
func paramIn(field, name string) string {
	for _, item := range splitOutsideQuotes(field, ',') {
		for _, part := range splitOutsideQuotes(item, ';') {
			key, value, found := strings.Cut(strings.TrimSpace(part), "=")
			if found && strings.EqualFold(strings.TrimSpace(key), name) {
				return strings.Trim(strings.TrimSpace(value), `"`)
			}
		}
	}
	return ""
}

// addressIn is the address a value names, with or without a port after it.
// 0.0.0.0 and :: name no exit, and an IPv4 address written as IPv6 is the
// IPv4 address, so that two ways of writing one address are one exit.
func addressIn(value string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		withPort, portErr := netip.ParseAddrPort(value)
		addr, err = withPort.Addr(), portErr
	}
	named := err == nil && addr.Zone() == ""
	addr = addr.Unmap()
	return addr, named && !addr.IsUnspecified()
}

// hashOfAnAddress is what a proxy's hash of an address looks like, such as
// Bright Data's raecd029229048fbbfd0b932221a3e40a, and nameOfAnExit what any
// other name for where a tunnel comes out may be made of: nothing a terminal
// would take for an instruction.
var (
	hashOfAnAddress = regexp.MustCompile(`^[A-Za-z0-9]{16,128}$`)
	nameOfAnExit    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)
