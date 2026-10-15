package main

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
)

// Where a request came out, when its proxy did not say it as an address.
//
// Asked, then, but only where nothing but the same exit can answer: of the
// site itself, over the very connection the request went out on, or of the
// proxy's own service, through the exit the proxy named. Asking anybody else
// on a connection of its own would be asking about another connection, and a
// proxy that hands each connection an address of its own would answer with
// somebody else's. What to ask, and of whom, is in exit-headers.json, as the
// fields are: a probe a file does not have is not made.

// cameOut is where a request through a proxy came out, and why that is not
// known when it is not: what the proxy said, the address behind a name it
// said when the file says how to ask for it, and what the site says over the
// same connection when the proxy said nothing.
func (b runner) cameOut(ctx context.Context, client *tlsforge.Client, proxy string, tries []try,
	res *tlsforge.Response, lane *traceLane,
) (egress, string) {
	var answer map[string][]string
	if res != nil {
		answer = res.Header
	}
	found, why, field := exitThrough(tries, answer, b.exits.Fields)
	switch {
	case found.IP == "" && found.Hash != "" && field.Resolve != nil:
		return b.names.resolve(ctx, b.clients.flags, proxy, found, *field.Resolve, lane), ""
	case why != "" && res != nil:
		if probed := b.probe(ctx, client, res, tries[len(tries)-1].Conn.Tunnel, lane); probed.Known() {
			return probed, ""
		}
	}
	return found, why
}

// probe asks the site a request went to where it came from, for a site the
// file says answers that, and believes the answer only when it came back over
// the tunnel the request went out on: through another, it would be another
// exit's.
func (b runner) probe(ctx context.Context, client *tlsforge.Client, res *tlsforge.Response, tunnel uint64,
	lane *traceLane,
) egress {
	site, err := url.Parse(res.URL)
	if err != nil {
		return egress{}
	}
	for _, p := range b.exits.Probes {
		if len(res.Header[strings.ToLower(p.When)]) == 0 {
			continue
		}
		asked := site.Scheme + "://" + site.Host + p.Path
		var mu sync.Mutex
		var went tlsforge.ConnInfo
		answer, err := client.Do(&tlsforge.Request{Context: ctx, URL: asked, Trace: &tlsforge.Trace{
			GotConn: func(conn tlsforge.ConnInfo) {
				mu.Lock()
				defer mu.Unlock()
				went = conn
			},
		}})
		mu.Lock()
		same := tunnel != 0 && went.Tunnel == tunnel
		mu.Unlock()
		about := traceArgs{"url": safeURL(asked), "same_connection": same}
		var found egress
		switch {
		case err != nil:
			about["error"] = err.Error()
		case same && answer.OK():
			found = p.read(answer.Body)
			found.By = strings.TrimSpace(p.Provider+" "+p.Path) + ", on the same connection"
			about["ip"] = found.IP
		}
		lane.instant("exit-probe", "net", about)
		if found.Known() {
			return found
		}
	}
	return egress{}
}

// resolver turns the names proxies give their exits into addresses, asking
// once for each name: a name is the same exit, and so the same address.
type resolver struct {
	mu   sync.Mutex
	done map[string]*resolution
}

// resolution is what one name was found to stand for.
type resolution struct {
	once  sync.Once
	found egress
}

// resolve is the name a proxy gave, with the address it stands for when the
// proxy's own service says it through the exit of that name.
func (r *resolver) resolve(ctx context.Context, flags clientFlags, proxy string, named egress, how exitResolve,
	lane *traceLane,
) egress {
	r.mu.Lock()
	if r.done == nil {
		r.done = map[string]*resolution{}
	}
	key := proxy + " " + named.Hash
	one, seen := r.done[key]
	if !seen {
		one = &resolution{}
		r.done[key] = one
	}
	r.mu.Unlock()

	one.once.Do(func() {
		one.found = named
		about := traceArgs{"name": named.Hash, "url": safeURL(how.URL)}
		pinned, ok := pinnedProxy(proxy, how.User, named.Hash)
		if !ok {
			// Asking through the proxy as it is would be asking another exit.
			about["error"] = "the name cannot be put in the proxy's user name"
			lane.instant("exit-resolve", "net", about)
			return
		}
		body, err := askThrough(ctx, flags, pinned, how.URL)
		if err != nil {
			about["error"] = redactError(err, proxy)
		} else if found := how.read(body); found.IP != "" {
			one.found.IP, one.found.Country = found.IP, found.Country
			one.found.By = addressService{URL: how.URL}.name() + ", through the exit the proxy named"
			about["ip"] = found.IP
		}
		lane.instant("exit-resolve", "net", about)
	})
	return one.found
}

// pinnedProxy is the proxy with the user name a resolve asks with: {user} the
// one the run was given, {value} the name to go out through. Not when there
// is no such proxy: a URL that does not parse, or a name with a colon in it,
// which a user name cannot hold, since Basic authentication ends the name at
// its first colon.
func pinnedProxy(proxy, user, value string) (string, bool) {
	u, err := url.Parse(proxy)
	if err != nil || strings.Contains(value, ":") {
		return "", false
	}
	pinned := strings.NewReplacer("{user}", u.User.Username(), "{value}", value).Replace(user)
	if password, set := u.User.Password(); set {
		u.User = url.UserPassword(pinned, password)
	} else {
		u.User = url.User(pinned)
	}
	return u.String(), true
}

// askThrough asks for one page through a proxy, with the run's profile and
// none of its session, as where a run comes out is asked, and no longer than
// that is waited for.
func askThrough(ctx context.Context, flags clientFlags, proxy, rawURL string) ([]byte, error) {
	asker, err := flags.asker(proxy)
	if err != nil {
		return nil, err
	}
	defer func() { _ = asker.Close() }()
	ctx, cancel := context.WithTimeout(ctx, exitLookupWait)
	defer cancel()
	res, err := asker.Do(&tlsforge.Request{Context: ctx, URL: rawURL})
	if err != nil {
		return nil, err
	}
	if !res.OK() {
		return nil, fmt.Errorf("%s: HTTP %d", rawURL, res.Status)
	}
	return res.Body, nil
}
