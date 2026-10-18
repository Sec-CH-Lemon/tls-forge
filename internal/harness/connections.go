package harness

import (
	"context"
	"io"
)

// MeasureConnections is what b asks of a server for each scenario of
// connections named in only, or every one, over HTTP/2 and over HTTP/1.1
// alone, with the connection each request came on: what
// testdata/chrome155-connections.json holds for them. A browser that can take
// the bench's certificate as a site's is measured so.
func MeasureConnections(ctx context.Context, b Browser, only []string, progress io.Writer) (map[string]MeasuredScenario, error) {
	return measure(ctx, b, connectionCatalogue, only, measured, progress)
}

// lobby is where a scenario of connections starts: a page of its origin that
// goes on to the run page two seconds after it has loaded. Chrome closes every
// connection it is not using each time its certificate verifier is told
// something new, which it is several times in the first few hundred
// milliseconds after it starts ("Cert verifier changed" in its net log): the
// run page's own connection could be closed under it.
const lobby = "{A}/p/lobby?after=2&next=/run/{ID}"

// onConnections is a scenario of connections, run from the lobby: its run
// page, and what its script asks for.
func onConnections(note, script string) scenario {
	return scenario{note: note, start: lobby, script: script, connections: true}
}

// connectionCatalogue is every scenario of connections measured, by its name
// in the fixture, its URLs filled in as the catalogue's are.
var connectionCatalogue = map[string]scenario{
	// The page's own origin.
	"conn-fetch":           onConnections("a page, then fetch() of its origin", "fetch('{A}/p/{ID}').then(done);"),
	"conn-fetch-omit":      onConnections("a page, then fetch() of its origin with credentials omit", "fetch('{A}/p/{ID}',{credentials:'omit'}).then(done);"),
	"conn-fetch-include":   onConnections("a page, then fetch() of its origin with credentials include", "fetch('{A}/p/{ID}',{credentials:'include'}).then(done);"),
	"conn-xhr":             onConnections("a page, then an XHR of its origin", "const x=new XMLHttpRequest();x.open('GET','{A}/p/{ID}');x.onloadend=done;x.send();"),
	"conn-xhr-credentials": onConnections("a page, then an XHR of its origin withCredentials", "const x=new XMLHttpRequest();x.open('GET','{A}/p/{ID}');x.withCredentials=true;x.onloadend=done;x.send();"),
	"conn-omit-and-not": onConnections("a page, then fetch() of its origin with credentials omit, one with credentials same-origin, and one omit again",
		"fetch('{A}/p/{ID}-1',{credentials:'omit'}).then(()=>fetch('{A}/p/{ID}-2')).then(()=>fetch('{A}/p/{ID}-3',{credentials:'omit'})).then(done);"),
	"conn-nav-after-omit": {note: "a page, fetch() of its origin with credentials omit, then location.href to its origin", start: lobby,
		script: "fetch('{A}/p/{ID}-fetch',{credentials:'omit'}).then(()=>{location.href='{A}/p/{ID}-end';});", wait: "/p/{ID}-end",
		connections: true},
	"conn-nav-same-site": {note: "a page, then location.href to another origin of its site", start: lobby,
		script: "location.href='{S}/p/{ID}-end';", wait: "/p/{ID}-end", connections: true},
	"conn-nav-cross-site": {note: "a page, then location.href to another site", start: lobby,
		script: "location.href='{X}/p/{ID}-end';", wait: "/p/{ID}-end", connections: true},
	"conn-nav-cross-site-after-include": {note: "a page, fetch() of another site with credentials include, then location.href there", start: lobby,
		script: "fetch('{X}/cors/{ID}-1',{credentials:'include'}).then(()=>{location.href='{X}/p/{ID}-end';});", wait: "/p/{ID}-end",
		connections: true},
	"conn-nav-redirect-cross-site": {note: "a page, then location.href to its origin, 302 to another site", start: lobby,
		script: "location.href='{A}/r/302/{ID}?to={X}/p/{ID}-end';", wait: "/p/{ID}-end", connections: true},
	"conn-nav-redirect-cross-site-after-include": {note: "a page, fetch() of another site with credentials include, then location.href to its origin, 302 to that site", start: lobby,
		script: "fetch('{X}/cors/{ID}-1',{credentials:'include'}).then(()=>{location.href='{A}/r/302/{ID}?to={X}/p/{ID}-end';});", wait: "/p/{ID}-end",
		connections: true},

	// Another origin of the page's site, and another site: in cors mode a
	// request kept to its own origin carries no credentials there, nor does
	// one in no-cors mode.
	"conn-fetch-same-site":          onConnections("a page, then fetch() of another origin of its site", "fetch('{S}/cors/{ID}').then(done);"),
	"conn-fetch-same-site-include":  onConnections("a page, then fetch() of another origin of its site with credentials include", "fetch('{S}/cors/{ID}',{credentials:'include'}).then(done);"),
	"conn-fetch-same-site-no-cors":  onConnections("a page, then fetch() of another origin of its site in no-cors mode", "fetch('{S}/p/{ID}',{mode:'no-cors'}).then(done);"),
	"conn-fetch-cross-site":         onConnections("a page, then fetch() of another site", "fetch('{X}/cors/{ID}').then(done);"),
	"conn-fetch-cross-site-include": onConnections("a page, then fetch() of another site with credentials include", "fetch('{X}/cors/{ID}',{credentials:'include'}).then(done);"),
	"conn-fetch-cross-site-no-cors": onConnections("a page, then fetch() of another site in no-cors mode", "fetch('{X}/p/{ID}',{mode:'no-cors'}).then(done);"),
	"conn-xhr-cross-site":           onConnections("a page, then an XHR of another site", "const x=new XMLHttpRequest();x.open('GET','{X}/cors/{ID}');x.onloadend=done;x.send();"),
	"conn-xhr-cross-site-credentials": onConnections("a page, then an XHR of another site withCredentials",
		"const x=new XMLHttpRequest();x.open('GET','{X}/cors/{ID}');x.withCredentials=true;x.onloadend=done;x.send();"),
	"conn-fetch-cross-site-both": onConnections("a page, then fetch() of another site with credentials include, one with credentials same-origin, one in no-cors mode, and one with credentials include again",
		"fetch('{X}/cors/{ID}-1',{credentials:'include'}).then(()=>fetch('{X}/cors/{ID}-2')).then(()=>fetch('{X}/p/{ID}-3',{mode:'no-cors'})).then(()=>fetch('{X}/cors/{ID}-4',{credentials:'include'})).then(done);"),

	// Requests that carry no credentials to a second name, after one to a
	// first.
	"conn-fetch-cross-site-then-same-site": onConnections("a page, fetch() of another site, then fetch() of another origin of its site, neither with credentials",
		"fetch('{X}/cors/{ID}-1').then(()=>fetch('{S}/cors/{ID}-2')).then(done);"),
	"conn-fetch-omit-then-cross-site": onConnections("a page, fetch() of its origin with credentials omit, then fetch() of another site",
		"fetch('{A}/p/{ID}-1',{credentials:'omit'}).then(()=>fetch('{X}/cors/{ID}-2')).then(done);"),

	// CORS preflights, which carry no credentials.
	"conn-preflight": onConnections("a page, then fetch() POST of JSON to another site: the preflight, then the request",
		"fetch('{X}/cors/{ID}?maxage=0',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).then(done);"),
	"conn-preflight-include": onConnections("a page, then fetch() POST of JSON to another site with credentials include: the preflight, then the request",
		"fetch('{X}/cors/{ID}?maxage=0',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}',credentials:'include'}).then(done);"),
	"conn-preflight-include-after-cors": onConnections("a page, fetch() of another site, then fetch() POST of JSON there with credentials include: the preflight, then the request",
		"fetch('{X}/cors/{ID}-1').then(()=>fetch('{X}/cors/{ID}-2?maxage=0',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}',credentials:'include'})).then(done);"),

	// Redirects to another site, after a request there that carried no
	// credentials.
	"conn-redirect-to-cross-site": onConnections("a page, fetch() of another site, then fetch() of its origin, 302 to that site",
		"fetch('{X}/cors/{ID}-1').then(()=>fetch('{A}/r/302/{ID}?to={X}/cors/{ID}-2')).then(done);"),
	"conn-redirect-include-to-cross-site": onConnections("a page, fetch() of another site, then fetch() of its origin with credentials include, 302 to that site",
		"fetch('{X}/cors/{ID}-1').then(()=>fetch('{A}/r/302/{ID}?to={X}/cors/{ID}-2',{credentials:'include'})).then(done);"),

	// TLS sessions: ?close ends a connection once answered, and a pause lets
	// the next request see it ended.
	"conn-resume": onConnections("a page, fetch() of its origin whose connection then ends, another, fetch() of its origin with credentials omit whose connection then ends, and another omit",
		"const pause=()=>new Promise(r=>setTimeout(r,300));fetch('{A}/p/{ID}-1?close=1').then(pause).then(()=>fetch('{A}/p/{ID}-2')).then(()=>fetch('{A}/p/{ID}-3?close=1',{credentials:'omit'})).then(pause).then(()=>fetch('{A}/p/{ID}-4',{credentials:'omit'})).then(done);"),
}
