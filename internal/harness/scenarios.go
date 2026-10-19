package harness

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// scenario is a page a browser is asked to open, and what it is to do there.
type scenario struct {
	// note says what the scenario is.
	note string
	// html and script are the run page's body, its script once the page has
	// loaded; done() asks for /done/ID.
	html, script string
	// referrer is the run page's referrer policy, said in a <meta>.
	referrer string
	// start is the URL opened, the run page /run/ID of the origin {A} unless
	// said; wait is the path whose request ends the scenario, /done/ID unless
	// said, once it has been asked for times times, or once; pre is a URL
	// opened first, in the same profile, for what it leaves; settle, for a
	// scenario that waits for nothing, how long it is left to run.
	start, wait, pre string
	times            int
	settle           time.Duration
	// connections is a scenario of connections: run in a browser that takes
	// the bench's certificate as a site's, it keeps its run page and says
	// which connection each request came on.
	connections bool
	// table is the size of the HPACK table the server's SETTINGS let the
	// browser have, for a scenario that asks for one; quiet gives the run
	// page an icon of its own, so that the browser asks for no /favicon.ico.
	table uint32
	quiet bool
}

// form is a form of two fields, its method, action and encoding filled in.
const form = `<form id=f method=%s action="%s" %s><input name=a value=1><input name=b value="x y"></form>`

func formHTML(method, action, enctype string) string {
	e := ""
	if enctype != "" {
		e = `enctype="` + enctype + `"`
	}
	return fmt.Sprintf(form, method, action, e)
}

const submit = "document.getElementById('f').submit();"

// catalogue is every scenario measured, by its name in the fixture. In its
// URLs {A} is https://www.example.com and {S} https://api.example.com, one
// site, {X} https://www.example.net, another, {C} {X} with credentials, {U}
// {A} with the ones the pages under /auth/ take, u:p, and {W} {A} with others,
// all on the port of the protocol measured; {H} is http://www.example.com,
// {L} http://localhost, {D} http://app.localhost, a name under .localhost,
// {4} http://127.0.0.1 and {6} http://[::1], on the plain port; and {ID} the
// scenario's name.
var catalogue = map[string]scenario{
	// Navigations.
	"nav-direct":                     {note: "a URL given on the command line", start: "{A}/p/nav-direct", wait: "/p/nav-direct"},
	"nav-direct-cookies":             {note: "the same, a second launch after a visit that set cookies", pre: "{A}/p/set?cookie=1", start: "{A}/p/nav-direct-cookies", wait: "/p/nav-direct-cookies"},
	"nav-direct-plain":               {note: "a URL given on the command line, plain http", start: "{H}/p/nav-direct-plain", wait: "/p/nav-direct-plain"},
	"nav-direct-localhost":           {note: "a URL given on the command line, http://localhost", start: "{L}/p/nav-direct-localhost", wait: "/p/nav-direct-localhost"},
	"nav-direct-dot-localhost":       {note: "a URL given on the command line, http to a name under .localhost", start: "{D}/p/nav-direct-dot-localhost", wait: "/p/nav-direct-dot-localhost"},
	"nav-direct-ipv4":                {note: "a URL given on the command line, http to 127.0.0.1", start: "{4}/p/nav-direct-ipv4", wait: "/p/nav-direct-ipv4"},
	"nav-direct-ipv6":                {note: "a URL given on the command line, http to [::1]", start: "{6}/p/nav-direct-ipv6", wait: "/p/nav-direct-ipv6"},
	"nav-same-origin":                {note: "location.href to a page of the same origin", script: "location.href='{A}/p/nav-same-origin';", wait: "/p/nav-same-origin"},
	"nav-same-origin-cookies":        {note: "the same, with cookies the run page set", start: "{A}/run/{ID}?cookie=1", script: "location.href='{A}/p/nav-same-origin-cookies';", wait: "/p/nav-same-origin-cookies"},
	"nav-same-site":                  {note: "location.href to another origin of the same site", script: "location.href='{S}/p/nav-same-site';", wait: "/p/nav-same-site"},
	"nav-cross-site":                 {note: "location.href to another site", script: "location.href='{X}/p/nav-cross-site';", wait: "/p/nav-cross-site"},
	"nav-downgrade":                  {note: "location.href from https to http on the same host", script: "location.href='{H}/p/nav-downgrade';", wait: "/p/nav-downgrade"},
	"nav-ref-no-referrer":            {note: "same origin, referrer policy no-referrer", referrer: "no-referrer", script: "location.href='{A}/p/nav-ref-no-referrer';", wait: "/p/nav-ref-no-referrer"},
	"nav-ref-origin":                 {note: "same origin, referrer policy origin", referrer: "origin", script: "location.href='{A}/p/nav-ref-origin';", wait: "/p/nav-ref-origin"},
	"nav-ref-unsafe-url-cross-site":  {note: "another site, referrer policy unsafe-url", referrer: "unsafe-url", script: "location.href='{X}/p/nav-ref-unsafe-url-cross-site';", wait: "/p/nav-ref-unsafe-url-cross-site"},
	"nav-ref-same-origin-cross-site": {note: "another site, referrer policy same-origin", referrer: "same-origin", script: "location.href='{X}/p/nav-ref-same-origin-cross-site';", wait: "/p/nav-ref-same-origin-cross-site"},
	"nav-ref-strict-origin":          {note: "same origin, referrer policy strict-origin", referrer: "strict-origin", script: "location.href='{A}/p/nav-ref-strict-origin';", wait: "/p/nav-ref-strict-origin"},

	// Forms, submitted by script.
	"form-post-same-origin":         {note: "a form posted to the same origin", html: formHTML("post", "{A}/p/form-post-same-origin", ""), script: submit, wait: "/p/form-post-same-origin"},
	"form-post-same-origin-cookies": {note: "the same, with cookies", start: "{A}/run/{ID}?cookie=1", html: formHTML("post", "{A}/p/form-post-same-origin-cookies", ""), script: submit, wait: "/p/form-post-same-origin-cookies"},
	"form-post-same-site":           {note: "a form posted to another origin of the same site", html: formHTML("post", "{S}/p/form-post-same-site", ""), script: submit, wait: "/p/form-post-same-site"},
	"form-post-cross-site":          {note: "a form posted to another site", html: formHTML("post", "{X}/p/form-post-cross-site", ""), script: submit, wait: "/p/form-post-cross-site"},
	"form-get-same-origin":          {note: "a form sent with GET to the same origin", html: formHTML("get", "{A}/p/form-get-same-origin", ""), script: submit, wait: "/p/form-get-same-origin"},
	"form-get-same-origin-cookies":  {note: "a form sent with GET to the same origin, with cookies", start: "{A}/run/{ID}?cookie=1", html: formHTML("get", "{A}/p/form-get-same-origin-cookies", ""), script: submit, wait: "/p/form-get-same-origin-cookies"},
	"form-post-multipart":           {note: "a multipart form posted to the same origin", html: formHTML("post", "{A}/p/form-post-multipart", "multipart/form-data"), script: submit, wait: "/p/form-post-multipart"},
	"form-post-text":                {note: "a text/plain form posted to the same origin", html: formHTML("post", "{A}/p/form-post-text", "text/plain"), script: submit, wait: "/p/form-post-text"},

	// fetch().
	"fetch-get-same-origin":                  {note: "fetch() of the same origin", script: "fetch('{A}/p/fetch-get-same-origin').then(done);"},
	"fetch-post-same-origin-json":            {note: "fetch() POST of JSON to the same origin", script: "fetch('{A}/p/fetch-post-same-origin-json',{method:'POST',headers:{'Content-Type':'application/json'},body:'{\"a\":1}'}).then(done);"},
	"fetch-post-same-origin-text":            {note: "fetch() POST of a string to the same origin", script: "fetch('{A}/p/fetch-post-same-origin-text',{method:'POST',body:'a=1'}).then(done);"},
	"fetch-post-same-origin-form":            {note: "fetch() POST of URLSearchParams to the same origin", script: "fetch('{A}/p/fetch-post-same-origin-form',{method:'POST',body:new URLSearchParams({a:'1',b:'x y'})}).then(done);"},
	"fetch-get-same-origin-header":           {note: "fetch() of the same origin with X-Foo", script: "fetch('{A}/p/fetch-get-same-origin-header',{headers:{'X-Foo':'bar'}}).then(done);"},
	"fetch-put-same-origin":                  {note: "fetch() PUT of JSON to the same origin", script: "fetch('{A}/p/fetch-put-same-origin',{method:'PUT',headers:{'Content-Type':'application/json'},body:'{}'}).then(done);"},
	"fetch-get-same-site":                    {note: "fetch() of another origin of the same site, CORS simple", script: "fetch('{S}/cors/fetch-get-same-site').then(done);"},
	"fetch-get-cross-site":                   {note: "fetch() of another site, CORS simple", script: "fetch('{X}/cors/fetch-get-cross-site').then(done);"},
	"fetch-post-cross-site-json":             {note: "fetch() POST of JSON to another site: preflight allowed", script: "fetch('{X}/cors/fetch-post-cross-site-json?maxage=0',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).then(done);"},
	"fetch-post-cross-site-json-denied":      {note: "the same, preflight refused", script: "fetch('{X}/cors/fetch-post-cross-site-json-denied?deny=1',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).catch(()=>0).then(done);"},
	"fetch-post-cross-site-json-cached":      {note: "two such POSTs, the preflight cached for 600 s", script: "const o={method:'POST',headers:{'Content-Type':'application/json'},body:'{}'};fetch('{X}/cors/fetch-post-cross-site-json-cached?maxage=600',o).then(()=>fetch('{X}/cors/fetch-post-cross-site-json-cached?maxage=600',o)).then(done);"},
	"fetch-get-cross-site-header":            {note: "fetch() of another site with X-Foo: preflight", script: "fetch('{X}/cors/fetch-get-cross-site-header?maxage=0',{headers:{'X-Foo':'bar'}}).then(done);"},
	"fetch-get-cross-site-credentials":       {note: "fetch() of another site with credentials include, after one that set cookies", script: "fetch('{X}/cors/set?cookie=1',{credentials:'include'}).then(()=>fetch('{X}/cors/fetch-get-cross-site-credentials',{credentials:'include'})).then(done);"},
	"fetch-get-cross-site-omit":              {note: "fetch() of another site with credentials omit, after one that set cookies", script: "fetch('{X}/cors/set?cookie=1',{credentials:'include'}).then(()=>fetch('{X}/cors/fetch-get-cross-site-omit',{credentials:'omit'})).then(done);"},
	"fetch-get-cross-site-same-origin-creds": {note: "fetch() of another site, credentials same-origin, after one that set cookies", script: "fetch('{X}/cors/set?cookie=1',{credentials:'include'}).then(()=>fetch('{X}/cors/fetch-get-cross-site-same-origin-creds')).then(done);"},
	"fetch-get-cross-site-no-cors":           {note: "fetch() of another site in no-cors mode", script: "fetch('{X}/p/fetch-get-cross-site-no-cors',{mode:'no-cors'}).then(done);"},
	"fetch-get-same-origin-cookies":          {note: "fetch() of the same origin with cookies", start: "{A}/run/{ID}?cookie=1", script: "fetch('{A}/p/fetch-get-same-origin-cookies').then(done);"},

	// XMLHttpRequest.
	"xhr-get-same-origin":         {note: "XHR GET of the same origin", script: "const x=new XMLHttpRequest();x.open('GET','{A}/p/xhr-get-same-origin');x.onloadend=done;x.send();"},
	"xhr-get-same-origin-cookies": {note: "XHR GET of the same origin with cookies", start: "{A}/run/{ID}?cookie=1", script: "const x=new XMLHttpRequest();x.open('GET','{A}/p/xhr-get-same-origin-cookies');x.onloadend=done;x.send();"},
	"xhr-post-same-origin":        {note: "XHR POST of a string to the same origin", script: "const x=new XMLHttpRequest();x.open('POST','{A}/p/xhr-post-same-origin');x.onloadend=done;x.send('a=1');"},
	"xhr-get-cross-site":          {note: "XHR GET of another site, CORS simple", script: "const x=new XMLHttpRequest();x.open('GET','{X}/cors/xhr-get-cross-site');x.onloadend=done;x.send();"},
	"xhr-post-cross-site-json":    {note: "XHR POST of JSON to another site: preflight", script: "const x=new XMLHttpRequest();x.open('POST','{X}/cors/xhr-post-cross-site-json?maxage=0');x.setRequestHeader('Content-Type','application/json');x.onloadend=done;x.send('{}');"},

	// Several headers set by script, and SameSite.
	"fetch-post-same-origin-headers": {note: "fetch() POST with X-B, X-A, Accept and Content-Type set, in that order", script: "fetch('{A}/p/fetch-post-same-origin-headers',{method:'POST',headers:[['X-B','1'],['X-A','2'],['Accept','application/json'],['Content-Type','text/plain']],body:'x'}).then(done);"},
	"nav-cross-site-samesite":        {note: "location.href to another site that set a cookie of each SameSite", start: "{X}/r/302/set?cookie=2&to={A}/run/{ID}", script: "location.href='{X}/p/nav-cross-site-samesite';", wait: "/p/nav-cross-site-samesite"},
	"form-post-cross-site-samesite":  {note: "a form posted to another site that set a cookie of each SameSite", start: "{X}/r/302/set?cookie=2&to={A}/run/{ID}", html: formHTML("post", "{X}/p/form-post-cross-site-samesite", ""), script: submit, wait: "/p/form-post-cross-site-samesite"},
	"fetch-get-cross-site-samesite":  {note: "fetch() with credentials include of another site that set a cookie of each SameSite", start: "{X}/r/302/set?cookie=2&to={A}/run/{ID}", script: "fetch('{X}/cors/fetch-get-cross-site-samesite',{credentials:'include'}).then(done);"},
	"nav-same-site-samesite":         {note: "location.href to another origin of the same site that set a cookie of each SameSite", start: "{S}/r/302/set?cookie=2&to={A}/run/{ID}", script: "location.href='{S}/p/nav-same-site-samesite';", wait: "/p/nav-same-site-samesite"},

	// Redirects of a navigation.
	"redir-nav-direct-301":        {note: "a command-line navigation, 301 to the same origin", start: "{A}/r/301/redir-nav-direct-301?to=/p/after-301", wait: "/p/after-301"},
	"redir-nav-direct-302":        {note: "a command-line navigation, 302 to the same origin", start: "{A}/r/302/redir-nav-direct-302?to=/p/after-302", wait: "/p/after-302"},
	"redir-nav-direct-303":        {note: "a command-line navigation, 303 to the same origin", start: "{A}/r/303/redir-nav-direct-303?to=/p/after-303", wait: "/p/after-303"},
	"redir-nav-direct-307":        {note: "a command-line navigation, 307 to the same origin", start: "{A}/r/307/redir-nav-direct-307?to=/p/after-307", wait: "/p/after-307"},
	"redir-nav-direct-308":        {note: "a command-line navigation, 308 to the same origin", start: "{A}/r/308/redir-nav-direct-308?to=/p/after-308", wait: "/p/after-308"},
	"redir-nav-direct-cross-site": {note: "a command-line navigation, 302 to another site, absolute", start: "{A}/r/302/redir-nav-direct-cross-site?to={X}/p/after-cross", wait: "/p/after-cross"},
	"redir-nav-direct-cookie":     {note: "a command-line navigation, a 302 that sets cookies", start: "{A}/r/302/redir-nav-direct-cookie?cookie=1&to=/p/after-cookie", wait: "/p/after-cookie"},
	"redir-nav-same-origin":       {note: "location.href, 302 to the same origin", script: "location.href='{A}/r/302/redir-nav-same-origin?to=/p/after-same';", wait: "/p/after-same"},
	"redir-nav-there-and-back":    {note: "location.href to another site, which sends it back with a 302", script: "location.href='{X}/r/302/redir-nav-there-and-back?to={A}/p/after-back';", wait: "/p/after-back"},
	"redir-nav-downgrade":         {note: "location.href, 302 from https to http", script: "location.href='{A}/r/302/redir-nav-downgrade?to={H}/p/after-down';", wait: "/p/after-down"},
	// Ended once the 20th request is asked for, and a little after, as every
	// scenario is: Chrome reloads the error page it shows a second later, and
	// again five seconds after that, each a navigation of its own that the
	// fixture leaves out. One that followed more redirects would ask for them
	// in the same moment.
	"redir-nav-chain": {note: "a command-line navigation into a chain of 302s that does not end: twenty requests, the twentieth redirect not followed (net::ERR_TOO_MANY_REDIRECTS); the error page then reloaded the last URL, and that reload is left out",
		start: "{A}/chain/0", wait: "/chain/19"},

	// Redirects of a typed navigation between plain http, https and
	// http://localhost, where what goes only to a potentially trustworthy URL
	// comes and goes.
	"redir-nav-direct-downgrade":          {note: "a command-line navigation, 302 from https to http", start: "{A}/r/302/redir-nav-direct-downgrade?to={H}/p/after-direct-down", wait: "/p/after-direct-down"},
	"redir-nav-direct-upgrade":            {note: "a command-line navigation, 302 from http to https", start: "{H}/r/302/redir-nav-direct-upgrade?to={A}/p/after-direct-up", wait: "/p/after-direct-up"},
	"redir-nav-direct-to-localhost":       {note: "a command-line navigation, 302 from https to http://localhost", start: "{A}/r/302/redir-nav-direct-to-localhost?to={L}/p/after-direct-localhost", wait: "/p/after-direct-localhost"},
	"redir-nav-direct-plain-to-localhost": {note: "a command-line navigation, 302 from http to http://localhost", start: "{H}/r/302/redir-nav-direct-plain-to-localhost?to={L}/p/after-plain-localhost", wait: "/p/after-plain-localhost"},

	// Redirects of a form's POST.
	"redir-form-301":            {note: "a form POST, 301 to the same origin", html: formHTML("post", "{A}/r/301/redir-form-301?to=/p/form-after-301", ""), script: submit, wait: "/p/form-after-301"},
	"redir-form-302":            {note: "a form POST, 302 to the same origin", html: formHTML("post", "{A}/r/302/redir-form-302?to=/p/form-after-302", ""), script: submit, wait: "/p/form-after-302"},
	"redir-form-303":            {note: "a form POST, 303 to the same origin", html: formHTML("post", "{A}/r/303/redir-form-303?to=/p/form-after-303", ""), script: submit, wait: "/p/form-after-303"},
	"redir-form-307":            {note: "a form POST, 307 to the same origin", html: formHTML("post", "{A}/r/307/redir-form-307?to=/p/form-after-307", ""), script: submit, wait: "/p/form-after-307"},
	"redir-form-308":            {note: "a form POST, 308 to the same origin", html: formHTML("post", "{A}/r/308/redir-form-308?to=/p/form-after-308", ""), script: submit, wait: "/p/form-after-308"},
	"redir-form-307-cross-site": {note: "a form POST, 307 to another site", html: formHTML("post", "{A}/r/307/redir-form-307-cross-site?to={X}/p/form-after-307x", ""), script: submit, wait: "/p/form-after-307x"},

	// Redirects of fetch().
	"redir-fetch-same-origin-302":                  {note: "fetch() of the same origin, 302 to the same origin", script: "fetch('{A}/r/302/redir-fetch-same-origin-302?to=/p/fetch-after-302').then(done);"},
	"redir-fetch-same-origin-302-cookies":          {note: "fetch() of the same origin, 302 to the same origin, with cookies", start: "{A}/run/{ID}?cookie=1", script: "fetch('{A}/r/302/redir-fetch-same-origin-302-cookies?to=/p/fetch-after-302-cookies').then(done);"},
	"redir-fetch-post-307":                         {note: "fetch() POST of JSON, 307 to the same origin", script: "fetch('{A}/r/307/redir-fetch-post-307?to=/p/fetch-after-307',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).then(done);"},
	"redir-fetch-cors-redirect-refused":            {note: "fetch() of another site whose redirect says nothing of CORS", script: "fetch('{X}/r/302/redir-fetch-cors-redirect-refused?noacao=1&to={X}/cors/after-refused').catch(()=>0).then(done);"},
	"redir-fetch-preflighted-307":                  {note: "fetch() POST of JSON to another site, preflighted, 307 to a third origin", script: "fetch('{X}/r/307/redir-fetch-preflighted-307?to={S}/cors/after-307?maxage=0',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).catch(()=>0).then(done);"},
	"redir-nav-direct-through-another-site":        {note: "a command-line navigation that sets cookies on one site, goes through another and comes back", start: "{X}/r/302/set?cookie=2&to={A}/r/302/through?to={X}/p/back-through", wait: "/p/back-through"},
	"redir-fetch-same-origin-to-cross":             {note: "fetch() of the same origin, 302 to another site", script: "fetch('{A}/r/302/redir-fetch-same-origin-to-cross?to={X}/cors/after-a-x').catch(()=>0).then(done);"},
	"redir-fetch-post-same-origin-to-cross":        {note: "fetch() POST of JSON to the same origin, 307 to another site", script: "fetch('{A}/r/307/redir-fetch-post-same-origin-to-cross?to={X}/cors/after-post-a-x?maxage=0',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).catch(()=>0).then(done);"},
	"redir-fetch-there-and-back":                   {note: "fetch() of another site, which sends it back with a 302", script: "fetch('{X}/r/302/redir-fetch-there-and-back?to={A}/cors/after-x-a').catch(()=>0).then(done);"},
	"redir-nav-rp-no-referrer":                     {note: "location.href, a 302 that says Referrer-Policy: no-referrer", script: "location.href='{A}/r/302/redir-nav-rp-no-referrer?rp=no-referrer&to=/p/after-rp-none';", wait: "/p/after-rp-none"},
	"redir-nav-rp-unsafe-url":                      {note: "location.href from a page with a query, a 302 to another site that says Referrer-Policy: unsafe-url", start: "{A}/run/{ID}?q=1", script: "location.href='{A}/r/302/redir-nav-rp-unsafe-url?rp=unsafe-url&to={X}/p/after-rp-unsafe';", wait: "/p/after-rp-unsafe"},
	"redir-nav-rp-last-known":                      {note: "location.href, a 302 to another site that says Referrer-Policy: unsafe-url, nonsense", script: "location.href='{A}/r/302/redir-nav-rp-last-known?rp=unsafe-url,%20nonsense&to={X}/p/after-rp-last';", wait: "/p/after-rp-last"},
	"redir-nav-rp-upper":                           {note: "location.href, a 302 that says Referrer-Policy: NO-REFERRER", script: "location.href='{A}/r/302/redir-nav-rp-upper?rp=NO-REFERRER&to=/p/after-rp-upper';", wait: "/p/after-rp-upper"},
	"redir-fetch-rp-unsafe-url":                    {note: "fetch(), a 302 to another site that says Referrer-Policy: unsafe-url", script: "fetch('{A}/r/302/redir-fetch-rp-unsafe-url?rp=unsafe-url&to={X}/cors/after-rp-fetch').catch(()=>0).then(done);"},
	"nav-localhost-to-http":                        {note: "location.href from a page on http://localhost to an http site", start: "{L}/run/{ID}", script: "location.href='{H}/p/nav-localhost-to-http';", wait: "/p/nav-localhost-to-http"},
	"redir-nav-localhost-to-http":                  {note: "location.href from a page on http://localhost, 302 to an http site", start: "{L}/run/{ID}", script: "location.href='{L}/r/302/redir-nav-localhost-to-http?to={H}/p/after-localhost-http';", wait: "/p/after-localhost-http"},
	"redir-fetch-auth-cross-origin":                {note: "fetch() of the same origin with Authorization, 307 to another site", script: "fetch('{A}/r/307/redir-fetch-auth-cross-origin?to={X}/cors/after-auth?maxage=0',{headers:{'Authorization':'Bearer x'}}).catch(()=>0).then(done);"},
	"nav-https-to-localhost":                       {note: "location.href from an https page to http://localhost", script: "location.href='{L}/p/nav-https-to-localhost';", wait: "/p/nav-https-to-localhost"},
	"redir-nav-https-to-localhost":                 {note: "location.href from an https page, 302 to http://localhost", script: "location.href='{A}/r/302/redir-nav-https-to-localhost?to={L}/p/after-https-localhost';", wait: "/p/after-https-localhost"},
	"redir-fetch-cors-post-303":                    {note: "fetch() POST of text to another site, 303 to the same origin there", script: "fetch('{X}/r/303/redir-fetch-cors-post-303?to={X}/cors/after-cors-303',{method:'POST',body:'a=1'}).catch(()=>0).then(done);"},
	"redir-fetch-cors-post-302":                    {note: "fetch() POST of text to another site, 302 to the same origin there", script: "fetch('{X}/r/302/redir-fetch-cors-post-302?to={X}/cors/after-cors-302',{method:'POST',body:'a=1'}).catch(()=>0).then(done);"},
	"redir-fetch-cors-put-301":                     {note: "fetch() PUT of text to another site, preflighted, 301 to the same origin there", script: "fetch('{X}/r/301/redir-fetch-cors-put-301?to={X}/cors/after-cors-put-301?maxage=0',{method:'PUT',body:'a=1'}).catch(()=>0).then(done);"},
	"redir-fetch-location-credentials":             {note: "fetch() of another site, 302 to a URL with credentials", script: "fetch('{X}/r/302/redir-fetch-location-credentials?to={C}/cors/after-credentials').catch(()=>0).then(done);"},
	"redir-fetch-same-origin-mode-away":            {note: "fetch() in same-origin mode, 302 to another site", script: "fetch('{A}/r/302/redir-fetch-same-origin-mode-away?to={X}/cors/after-som',{mode:'same-origin'}).catch(()=>0).then(done);"},
	"redir-fetch-same-origin-location-credentials": {note: "fetch() of the same origin, 302 to the same origin with credentials", script: "fetch('{A}/r/302/redir-fetch-same-origin-location-credentials?to=https://u:p@www.example.com:'+location.port+'/cors/after-same-credentials').catch(()=>0).then(done);"},
	"redir-xhr-same-origin-location-credentials":   {note: "XHR of the same origin, 302 to the same origin with credentials", script: "const x=new XMLHttpRequest();x.open('GET','{A}/r/302/redir-xhr-same-origin-location-credentials?to=https://u:p@www.example.com:'+location.port+'/cors/after-xhr-same-credentials');x.onloadend=done;x.send();"},
	"redir-xhr-location-credentials":               {note: "XHR of another site, 302 to a URL with credentials", script: "const x=new XMLHttpRequest();x.open('GET','{X}/r/302/redir-xhr-location-credentials?to={C}/cors/after-xhr-credentials');x.onloadend=done;x.send();"},
	"redir-nav-location-credentials":               {note: "location.href, 302 to the same origin with credentials", script: "location.href='{A}/r/302/redir-nav-location-credentials?to=https://u:p@www.example.com:'+location.port+'/p/after-nav-credentials';", wait: "/p/after-nav-credentials"},
	"redir-fetch-include-same-origin-to-cross":     {note: "fetch() of the same origin with credentials, 302 to another site", script: "fetch('{A}/r/302/redir-fetch-include-same-origin-to-cross?to={X}/cors/after-include',{credentials:'include'}).catch(()=>0).then(done);"},
	"redir-xhr-same-origin-to-cross":               {note: "XHR of the same origin, 302 to another site", script: "const x=new XMLHttpRequest();x.open('GET','{A}/r/302/redir-xhr-same-origin-to-cross?to={X}/cors/after-xhr-a-x');x.onloadend=done;x.send();"},
	"redir-xhr-post-cross-303":                     {note: "XHR POST of text to another site, 303 to the same origin there", script: "const x=new XMLHttpRequest();x.open('POST','{X}/r/303/redir-xhr-post-cross-303?to={X}/cors/after-xhr-303');x.onloadend=done;x.send('a=1');"},
	"fetch-get-same-origin-authorization":          {note: "fetch() of the same origin with Authorization", script: "fetch('{A}/p/fetch-get-same-origin-authorization',{headers:{'Authorization':'Bearer x'}}).then(done);"},
	"xhr-get-same-origin-authorization":            {note: "XHR GET of the same origin with Authorization", script: "const x=new XMLHttpRequest();x.open('GET','{A}/p/xhr-get-same-origin-authorization');x.setRequestHeader('Authorization','Bearer x');x.onloadend=done;x.send();"},
	"redir-fetch-same-origin-to-cross-and-on":      {note: "fetch() of the same origin, 302 to another site, 302 on within it", script: "fetch('{A}/r/302/redir-fetch-same-origin-to-cross-and-on?to={X}/r/302/on?to={X}/cors/after-on').catch(()=>0).then(done);"},
	"redir-fetch-tainted-and-on":                   {note: "fetch() of another site, 302 to a third origin, 302 on within it", script: "fetch('{X}/r/302/redir-fetch-tainted-and-on?to={S}/r/302/on?to={S}/cors/after-tainted').catch(()=>0).then(done);"},
	"redir-fetch-there-and-back-cookies":           {note: "fetch() of another site that sends it back with a 302, cookies set on the page's origin", start: "{A}/run/{ID}?cookie=1", script: "fetch('{X}/r/302/redir-fetch-there-and-back-cookies?to={A}/cors/after-back-cookies').catch(()=>0).then(done);"},
	"redir-fetch-no-cors-back-cookies":             {note: "fetch() of another site in no-cors mode that sends it back with a 302, cookies set on the page's origin", start: "{A}/run/{ID}?cookie=1", script: "fetch('{X}/r/302/redir-fetch-no-cors-back-cookies?to={A}/p/after-no-cors-back-cookies',{mode:'no-cors'}).catch(()=>0).then(done);"},
	"redir-nav-narrowing":                          {note: "location.href to the same origin, 302 to another site, 302 back", script: "location.href='{A}/r/302/redir-nav-narrowing?to={X}/r/302/away?to={A}/p/after-narrowing';", wait: "/p/after-narrowing"},
	// Client hints a server asks for, with Accept-CH and Critical-CH.
	"ch-nav-all":                 {note: "a page that asks for every hint, then a navigation to its origin", start: "{A}/run/{ID}?accept=sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,sec-ch-ua-arch,sec-ch-ua-bitness,sec-ch-ua-full-version,sec-ch-ua-full-version-list,sec-ch-ua-model,sec-ch-ua-platform-version,sec-ch-ua-wow64,sec-ch-ua-form-factors,sec-ch-dpr,sec-ch-viewport-width,sec-ch-viewport-height,sec-ch-device-memory,sec-ch-prefers-color-scheme,sec-ch-prefers-reduced-motion,sec-ch-prefers-reduced-transparency,dpr,viewport-width,device-memory,rtt,downlink,ect,save-data", script: "location.href='{A}/p/ch-nav-all';", wait: "/p/ch-nav-all"},
	"ch-nav-some":                {note: "a page that asks for three hints in capitals, then a navigation to its origin", start: "{A}/run/{ID}?accept=Sec-CH-UA-Arch,%20Sec-CH-UA-Bitness,%20Sec-CH-UA-Model", script: "location.href='{A}/p/ch-nav-some';", wait: "/p/ch-nav-some"},
	"ch-nav-cross-site":          {note: "a page that asks for a hint, then a navigation to another site", start: "{A}/run/{ID}?accept=sec-ch-ua-arch", script: "location.href='{X}/p/ch-nav-cross-site';", wait: "/p/ch-nav-cross-site"},
	"ch-nav-same-site":           {note: "a page that asks for a hint, then a navigation to another origin of its site", start: "{A}/run/{ID}?accept=sec-ch-ua-arch", script: "location.href='{S}/p/ch-nav-same-site';", wait: "/p/ch-nav-same-site"},
	"ch-nav-cleared":             {note: "a page asks for a hint, a page of its origin asks for none, then a third", start: "{A}/run/{ID}?accept=sec-ch-ua-arch", script: "location.href='{A}/p/ch-clear?accept=&next=/p/ch-cleared-end';", wait: "/p/ch-cleared-end"},
	"ch-nav-replaced":            {note: "a page asks for a hint, a page of its origin for another, then a third", start: "{A}/run/{ID}?accept=sec-ch-ua-arch", script: "location.href='{A}/p/ch-replace?accept=sec-ch-ua-bitness&next=/p/ch-replaced-end';", wait: "/p/ch-replaced-end"},
	"ch-nav-unasked":             {note: "a page with no Accept-CH, a page of its origin, then a third", start: "{A}/run/{ID}?accept=sec-ch-ua-arch", script: "location.href='{A}/p/ch-unasked?next=/p/ch-unasked-end';", wait: "/p/ch-unasked-end"},
	"ch-critical-typed":          {note: "a typed navigation to a page that asks for a hint and says it is critical", start: "{A}/p/ch-critical-typed?accept=sec-ch-ua-arch&critical=sec-ch-ua-arch", wait: "/never", settle: 4000 * time.Millisecond},
	"ch-critical-unasked":        {note: "a typed navigation to a page that says a hint it does not ask for is critical", start: "{A}/p/ch-critical-unasked?accept=sec-ch-ua-bitness&critical=sec-ch-ua-arch", wait: "/never", settle: 4000 * time.Millisecond},
	"ch-critical-low":            {note: "a typed navigation to a page that says a hint sent by default is critical", start: "{A}/p/ch-critical-low?accept=sec-ch-ua-mobile&critical=sec-ch-ua-mobile", wait: "/never", settle: 4000 * time.Millisecond},
	"ch-critical-redirect":       {note: "a typed navigation, a 302 that asks for a hint and says it is critical", start: "{A}/r/302/ch-critical-redirect?accept=sec-ch-ua-arch&critical=sec-ch-ua-arch&to=/p/ch-after-critical-redirect", wait: "/never", settle: 4000 * time.Millisecond},
	"ch-redirect-accept":         {note: "a typed navigation, a 302 that asks for a hint", start: "{A}/r/302/ch-redirect-accept?accept=sec-ch-ua-arch&to=/p/ch-after-redirect", wait: "/never", settle: 4000 * time.Millisecond},
	"ch-critical-form-post":      {note: "a form POST to a page that asks for a hint and says it is critical", html: formHTML("post", "{A}/p/ch-critical-form-post?accept=sec-ch-ua-arch&critical=sec-ch-ua-arch", ""), script: submit, wait: "/never", settle: 4000 * time.Millisecond},
	"ch-fetch-same-origin":       {note: "a page that asks for a hint, then fetch() of its origin", start: "{A}/run/{ID}?accept=sec-ch-ua-arch", script: "fetch('{A}/p/ch-fetch-same-origin').then(done);"},
	"ch-fetch-cross-site":        {note: "a page that asks for a hint, then fetch() of another site", start: "{A}/run/{ID}?accept=sec-ch-ua-arch", script: "fetch('{X}/cors/ch-fetch-cross-site').then(done);"},
	"ch-fetch-critical":          {note: "fetch() of a page that asks for a hint and says it is critical", script: "fetch('{A}/p/ch-fetch-critical?accept=sec-ch-ua-arch&critical=sec-ch-ua-arch').then(()=>fetch('{A}/p/ch-fetch-after')).then(done);"},
	"ch-fetch-asks":              {note: "fetch() of a page that asks for a hint, then a navigation to the origin", script: "fetch('{A}/p/ch-fetch-asks?accept=sec-ch-ua-arch').then(()=>{location.href='{A}/p/ch-fetch-asks-after';});", wait: "/p/ch-fetch-asks-after"},
	"ch-persist":                 {note: "a second launch, after a page of the origin asked for a hint", pre: "{A}/p/ch-persist-set?accept=sec-ch-ua-arch", start: "{A}/p/ch-persist", wait: "/p/ch-persist"},
	"ch-fetch-three":             {note: "a page that asks for three hints, then fetch() of its origin", start: "{A}/run/{ID}?accept=sec-ch-ua-arch,sec-ch-ua-bitness,sec-ch-ua-model", script: "fetch('{A}/p/ch-fetch-three').then(done);"},
	"ch-fetch-all":               {note: "a page that asks for every hint, then fetch() of its origin", start: "{A}/run/{ID}?accept=sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,sec-ch-ua-arch,sec-ch-ua-bitness,sec-ch-ua-full-version,sec-ch-ua-full-version-list,sec-ch-ua-model,sec-ch-ua-platform-version,sec-ch-ua-wow64,sec-ch-ua-form-factors,sec-ch-dpr,sec-ch-viewport-width,sec-ch-viewport-height,sec-ch-device-memory,sec-ch-prefers-color-scheme,sec-ch-prefers-reduced-motion,sec-ch-prefers-reduced-transparency,dpr,viewport-width,device-memory,rtt,downlink,ect,save-data", script: "fetch('{A}/p/ch-fetch-all').then(done);"},
	"ch-fetch-post-json":         {note: "a page that asks for a hint, then fetch() POST of JSON to its origin", start: "{A}/run/{ID}?accept=sec-ch-ua-arch", script: "fetch('{A}/p/ch-fetch-post-json',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).then(done);"},
	"ch-xhr-same-origin":         {note: "a page that asks for a hint, then an XHR of its origin", start: "{A}/run/{ID}?accept=sec-ch-ua-arch", script: "const x=new XMLHttpRequest();x.open('GET','{A}/p/ch-xhr-same-origin');x.onloadend=done;x.send();"},
	"ch-form-post":               {note: "a page that asks for a hint, then a form posted to its origin", start: "{A}/run/{ID}?accept=sec-ch-ua-arch", html: formHTML("post", "{A}/p/ch-form-post", ""), script: submit, wait: "/p/ch-form-post"},
	"ch-form-get":                {note: "a page that asks for a hint, then a form sent by GET to its origin", start: "{A}/run/{ID}?accept=sec-ch-ua-arch", html: formHTML("get", "{A}/p/ch-form-get", ""), script: submit, wait: "/p/ch-form-get"},
	"ch-nav-all-redirect":        {note: "a page that asks for every hint, then a navigation to its origin that redirects there", start: "{A}/run/{ID}?accept=sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,sec-ch-ua-arch,sec-ch-ua-bitness,sec-ch-ua-full-version,sec-ch-ua-full-version-list,sec-ch-ua-model,sec-ch-ua-platform-version,sec-ch-ua-wow64,sec-ch-ua-form-factors,sec-ch-dpr,sec-ch-viewport-width,sec-ch-viewport-height,sec-ch-device-memory,sec-ch-prefers-color-scheme,sec-ch-prefers-reduced-motion,sec-ch-prefers-reduced-transparency,dpr,viewport-width,device-memory,rtt,downlink,ect,save-data", script: "location.href='{A}/r/302/ch-nav-all-redirect?to=/p/ch-after-all-redirect';", wait: "/p/ch-after-all-redirect"},
	"ch-critical-all":            {note: "a typed navigation to a page that asks for every hint and says one is critical", start: "{A}/p/ch-critical-all?accept=sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,sec-ch-ua-arch,sec-ch-ua-bitness,sec-ch-ua-full-version,sec-ch-ua-full-version-list,sec-ch-ua-model,sec-ch-ua-platform-version,sec-ch-ua-wow64,sec-ch-ua-form-factors,sec-ch-dpr,sec-ch-viewport-width,sec-ch-viewport-height,sec-ch-device-memory,sec-ch-prefers-color-scheme,sec-ch-prefers-reduced-motion,sec-ch-prefers-reduced-transparency,dpr,viewport-width,device-memory,rtt,downlink,ect,save-data&critical=sec-ch-ua-arch", wait: "/never", settle: 4000 * time.Millisecond},
	"ch-critical-cookie":         {note: "a typed navigation to a page that sets cookies, asks for a hint and says it is critical", start: "{A}/p/ch-critical-cookie?cookie=1&accept=sec-ch-ua-arch&critical=sec-ch-ua-arch", wait: "/never", settle: 4000 * time.Millisecond},
	"ch-nav-from-other-site":     {note: "a page asks for a hint, then goes to another site whose page sends it back", start: "{A}/run/{ID}?accept=sec-ch-ua-arch", script: "location.href='{X}/p/ch-away?next={A}/p/ch-back';", wait: "/p/ch-back"},
	"ch-fetch-from-other-site":   {note: "a second launch: a page of another site fetches an origin that asked for a hint", pre: "{A}/p/ch-third-set?accept=sec-ch-ua-arch", start: "{X}/run/{ID}", script: "fetch('{A}/cors/ch-third-party').then(done);"},
	"ch-critical-from-page":      {note: "location.href to a page that asks for a hint and says it is critical", script: "location.href='{A}/p/ch-critical-from-page?accept=sec-ch-ua-arch&critical=sec-ch-ua-arch';", wait: "/never", settle: 4000 * time.Millisecond},
	"ch-critical-after-redirect": {note: "a typed navigation, 302 to a page that asks for a hint and says it is critical", start: "{A}/r/302/ch-critical-after-redirect?to=/p/ch-critical-landing?accept=sec-ch-ua-arch%26critical=sec-ch-ua-arch", wait: "/never", settle: 4000 * time.Millisecond},
	"ch-form-post-asks":          {note: "a form posted to a page that asks for a hint and moves on", html: formHTML("post", "{A}/p/ch-form-post-asks?accept=sec-ch-ua-arch&next=/p/ch-form-post-asks-end", ""), script: submit, wait: "/p/ch-form-post-asks-end"},
	"ch-plain-asks":              {note: "a typed navigation to a plain-http page that asks for a hint and moves on", start: "{H}/p/ch-plain-asks?accept=sec-ch-ua-arch&next=/p/ch-plain-asks-end", wait: "/p/ch-plain-asks-end"},
	"ch-redirect-to-asker":       {note: "a page of an origin that asked, then a navigation from another site redirected to it", start: "{A}/run/{ID}?accept=sec-ch-ua-arch", script: "location.href='{X}/r/302/ch-redirect-to-asker?to={A}/p/ch-redirect-to-asker-end';", wait: "/p/ch-redirect-to-asker-end"},
	"redir-fetch-cross-site-302": {note: "fetch() of another site, 302 to a third origin", script: "fetch('{X}/r/302/redir-fetch-cross-site-302?to={S}/cors/fetch-after-cross').then(done);"},

	// HTTP authentication: a page under /auth/ answers 401 with a Basic
	// challenge, of the realm "bench", until it is sent u:p.
	"auth-nav-typed":                   {note: "a URL with credentials given on the command line, a page that answers 401 until it is sent them, then a page of its directory and one outside it", start: "{U}/auth/{ID}/a?next=/auth/{ID}/b%3Fnext%3D/p/{ID}-end", wait: "/p/{ID}-end"},
	"auth-nav-typed-other-dir":         {note: "the same, then a page of another directory, of the same realm", start: "{U}/auth/{ID}/a?next=/auth/{ID}-other/b%3Fnext%3D/p/{ID}-end", wait: "/p/{ID}-end"},
	"auth-nav-wrong":                   {note: "a URL with credentials the page does not take, given on the command line", start: "{W}/auth/{ID}/a", wait: "/never", settle: 3000 * time.Millisecond},
	"auth-nav-digest":                  {note: "a URL with credentials given on the command line, a page that offers Digest and then Basic", start: "{U}/auth/{ID}/a?offer=digest", wait: "/never", settle: 3000 * time.Millisecond},
	"auth-nav-from-page":               {note: "location.href to a URL of the same origin with credentials, a page that answers 401 until it is sent them", script: "location.href='{U}/auth/{ID}/a?next=/p/{ID}-end';", wait: "/p/{ID}-end"},
	"auth-nav-cross-site-samesite":     {note: "location.href to a URL of another site with credentials, which set a cookie of each SameSite, a page that answers 401 until it is sent them", start: "{X}/r/302/set?cookie=2&to={A}/run/{ID}", script: "location.href='{C}/auth/{ID}/a?next=/p/{ID}-end';", wait: "/p/{ID}-end"},
	"auth-nav-redirect-to-credentials": {note: "a command-line navigation, 302 to a URL with credentials, a page that answers 401 until it is sent them", start: "{A}/r/302/{ID}?to={U}/auth/{ID}/a%3Fnext%3D/p/{ID}-end", wait: "/p/{ID}-end"},
	"auth-nav-redirect-after":          {note: "a URL with credentials given on the command line, a page that answers 401 until it is sent them, then 302 to a page of its directory", start: "{U}/auth/{ID}/a?to=/auth/{ID}/b%3Fnext%3D/p/{ID}-end", wait: "/p/{ID}-end"},
	"auth-form-post":                   {note: "a form posted to a URL of the same origin with credentials, a page that answers 401 until it is sent them", html: formHTML("post", "{U}/auth/{ID}/post?next=/p/{ID}-end", ""), script: submit, wait: "/p/{ID}-end"},
	"auth-xhr":                         {note: "XHR GET of a URL of the same origin with credentials, a page that answers 401 until it is sent them", script: "const x=new XMLHttpRequest();x.open('GET','{U}/auth/{ID}/x');x.onloadend=done;x.send();"},
	"auth-nav-later-same-dir":          {note: "a URL with credentials given on the command line, a page that answers 401 until it is sent them, then one of its directory by a URL without them", start: "{U}/auth/{ID}/a?next={A}/auth/{ID}/b%3Fnext%3D/p/{ID}-end", wait: "/never", settle: 4000 * time.Millisecond},
	"auth-nav-later-other-dir":         {note: "the same, then a page of another directory, of the same realm, by a URL without them", start: "{U}/auth/{ID}/a?next={A}/auth/{ID}-other/b%3Fnext%3D/p/{ID}-end", wait: "/never", settle: 4000 * time.Millisecond},

	// A 421 (Misdirected Request) under /misdirected/, as Misdirection
	// answers: once with a 401 answered between, and once with a cookie.
	"nav-misdirected-401-misdirected": {note: "location.href to a URL of the same origin with credentials, a page that answers 421 the first time, then 401 until it is sent them, and 421 the first time it is sent them",
		script: "location.href='{U}/misdirected/{ID}?first=1&auth=1&authfirst=1';", wait: "/misdirected/{ID}", times: 3},
	"nav-401-misdirected": {note: "location.href to a URL of the same origin with credentials, a page that answers 401 until it is sent them, and 421 the first time it is sent them",
		script: "location.href='{U}/misdirected/{ID}?auth=1&authfirst=1';", wait: "/misdirected/{ID}", times: 3},
	// Which answers' cookies are kept (?keep, ?pfkeep): a later request says.
	"set-cookie-fetch-omit": {note: "fetch() with credentials omit whose answer sets a cookie, then fetch() of the same origin",
		script: "fetch('{A}/p/{ID}?keep=omitted',{credentials:'omit'}).then(()=>fetch('{A}/p/{ID}-after')).then(done);"},
	"set-cookie-fetch-across-same-origin-creds": {note: "fetch() of another origin of the site, credentials same-origin, whose answer sets a cookie, then one with credentials include",
		script: "fetch('{S}/cors/{ID}?keep=crossed').then(()=>fetch('{S}/cors/{ID}-after',{credentials:'include'})).then(done);"},
	"set-cookie-preflight": {note: "a preflight whose answer sets a cookie, between fetch() calls of another origin with credentials include",
		script: "fetch('{S}/cors/{ID}-control?keep=control',{credentials:'include'}).then(()=>fetch('{S}/cors/{ID}?pfkeep=preflighted',{method:'POST',headers:{'X-Foo':'1'},body:'x',credentials:'include'})).then(()=>fetch('{S}/cors/{ID}-after',{credentials:'include'})).then(done);"},
	"set-cookie-fetch-cors-refused": {note: "fetch() of another origin with credentials include whose answer, which CORS refuses, sets a cookie, then one CORS allows",
		script: "fetch('{S}/cors/{ID}?keep=refused&noacao=1',{credentials:'include'}).catch(()=>0).then(()=>fetch('{S}/cors/{ID}-after',{credentials:'include'})).then(done);"},
	"set-cookie-redir-across-same-origin-creds": {note: "fetch() of the same origin, credentials same-origin, 302 to another origin of the site, each answer setting a cookie, then fetch() of each origin",
		script: "fetch('{A}/r/302/{ID}?keep=first&to={S}/cors/{ID}?keep=second').then(()=>fetch('{A}/p/{ID}-after')).then(()=>fetch('{S}/cors/{ID}-after',{credentials:'include'})).then(done);"},
	"fetch-misdirected-cookie": {note: "fetch() of the same origin, answered 421 the first time with a cookie, then fetch() of the same origin",
		script: "fetch('{A}/misdirected/{ID}?first=1&mcookie=1').then(()=>fetch('{A}/p/{ID}-after')).then(done);"},

	// Digest authentication: a page under /digest/OFFER/ asks for it as the
	// offer says (digestOffers), of the realm "bench", until it is answered
	// with u:p; then it goes on to a page of its origin by a URL without
	// credentials, which is sent what Chrome keeps for the realm.
	"auth-digest": {note: "a URL with credentials given on the command line, a page that asks for Digest alone, qop=auth and no algorithm, until it is answered with them, then two pages of its directory by URLs without them",
		start: "{U}/digest/auth/{ID}/a?next=/digest/auth/{ID}/b%3Fnext%3D/digest/auth/{ID}/c%253Fnext%253D/p/{ID}-end", wait: "/p/{ID}-end"},
	"auth-digest-md5":               digestThen("md5", "Digest with algorithm=MD5"),
	"auth-digest-md5-sess":          digestThen("md5-sess", "Digest with algorithm=MD5-sess"),
	"auth-digest-sha256":            digestThen("sha256", "Digest with algorithm=SHA-256"),
	"auth-digest-sha256-sess":       digestThen("sha256-sess", "Digest with algorithm=SHA-256-sess"),
	"auth-digest-no-qop":            digestThen("no-qop", "Digest with no qop, as RFC 2069 has it"),
	"auth-digest-auth-int":          digestThen("auth-int", "Digest with qop=auth-int alone"),
	"auth-digest-qop-list":          digestThen("qop-list", `Digest with qop="auth-int,auth"`),
	"auth-digest-opaque":            digestThen("opaque", "Digest with an opaque"),
	"auth-digest-userhash":          digestThen("userhash", "Digest with algorithm=SHA-256 and userhash=true"),
	"auth-digest-no-realm":          digestThen("no-realm", "Digest with no realm"),
	"auth-digest-unknown-algorithm": digestThen("unknown-algorithm", "Digest with algorithm=SHA-512-256, then Basic"),
	"auth-digest-no-nonce":          digestThen("no-nonce", "Digest with no nonce, then Basic"),
	"auth-digest-empty-value":       digestThen("empty-value", "Digest with a parameter of no value, then Basic"),
	"auth-digest-after-basic":       digestThen("after-basic", "Basic, then Digest"),
	"auth-digest-md5-first":         digestThen("md5-first", "Digest with algorithm=MD5, then Digest with algorithm=SHA-256"),
	"auth-digest-sha256-first":      digestThen("sha256-first", "Digest with algorithm=SHA-256, then Digest with algorithm=MD5"),
	"auth-digest-stale":             digestThen("stale", "Digest whose first nonce is out of date when answered, asked for again with another and stale=true"),
	"auth-digest-quoting":           digestThen("quoting", "Digest with names and values in other cases, a token for a value, escapes, a parameter said twice and others of no matter"),
	"auth-digest-unquoted":          digestThen("unquoted", `Digest with tokens for values, one with "=" in it, and a quote that does not end`),
	"auth-digest-stale-later": {note: "a URL with credentials given on the command line, a page that asks for Digest until it is answered with them, then two pages of its directory by URLs without them, the first answered with a nonce count of 2 that the page says is out of date",
		start: "{U}/digest/stale-later/{ID}/a?next=/digest/stale-later/{ID}/b%3Fnext%3D/digest/stale-later/{ID}/c%253Fnext%253D/p/{ID}-end", wait: "/p/{ID}-end"},
	"auth-digest-other-dir": {note: "a URL with credentials given on the command line, a page that asks for Digest until it is answered with them, then a page of another directory of the realm by a URL without them, then one of the first directory",
		start: "{U}/digest/auth/{ID}/a?next=/digest/auth/{ID}-other/b%3Fnext%3D/digest/auth/{ID}/c%253Fnext%253D/p/{ID}-end", wait: "/p/{ID}-end"},
	"auth-digest-form-post": {note: "a form posted to a URL of the same origin with credentials, a page that asks for Digest until it is answered with them",
		html: formHTML("post", "{U}/digest/auth/{ID}/post?next=/p/{ID}-end", ""), script: submit, wait: "/p/{ID}-end"},
	"auth-digest-redirect": {note: "a URL with credentials given on the command line, a page that asks for Digest until it is answered with them, then 302 to a page of its directory by a URL without them",
		start: "{U}/digest/auth/{ID}/a?to=/digest/auth/{ID}/b%3Fnext%3D/p/{ID}-end", wait: "/p/{ID}-end"},
	"auth-digest-basic-kept": {note: "a URL with credentials given on the command line, a page that asks for Basic until it is answered with them, then a page of another directory that asks for Digest of the same realm, by a URL without them",
		start: "{U}/auth/{ID}/a?next={A}/digest/auth/{ID}/b%3Fnext%3D/p/{ID}-end", wait: "/never", settle: 4000 * time.Millisecond},
	"auth-digest-ntlm": {note: "a URL with credentials given on the command line, a page that offers NTLM, then Digest, then Basic",
		start: "{U}/digest/ntlm/{ID}/a?next=/digest/ntlm/{ID}/b%3Fnext%3D/p/{ID}-end", wait: "/never", settle: 4000 * time.Millisecond},
	"auth-digest-negotiate": digestThen("negotiate", "Negotiate, then Digest, then Basic"),
	// Ended at the 32nd request, and a little after: Chrome then shows an
	// error page, which it reloads a second later, a navigation of its own
	// that the fixture leaves out.
	"auth-digest-stale-forever": {note: "a URL with credentials given on the command line, a page every Digest answer to which it says is out of date: 32 requests, the 32nd answer not sent (net::ERR_TOO_MANY_RETRIES); the error page then reloaded the URL, and that reload is left out",
		start: "{U}/digest/stale-forever/{ID}/a", wait: "/digest/stale-forever/{ID}/a", times: 32},
}

// digestThen is the scenario of a Digest offer: a URL with credentials given
// on the command line, of a page under /digest/OFFER/ that asks as asked says
// until it is answered with them, then a page of its directory by a URL
// without them.
func digestThen(offer, asked string) scenario {
	return scenario{note: "a URL with credentials given on the command line, a page that asks for " + asked +
		", until it is answered with them, then a page of its directory by a URL without them",
		start: "{U}/digest/" + offer + "/{ID}/a?next=/digest/" + offer + "/{ID}/b%3Fnext%3D/p/{ID}-end", wait: "/p/{ID}-end"}
}

// origins are the origins of a run whose TLS origins are on port, plain HTTP
// on plain, by the letter the catalogue names them by, and the ports
// themselves, P and Q.
func origins(port, plain int) map[string]string {
	tls, http := strconv.Itoa(port), strconv.Itoa(plain)
	return map[string]string{
		"P": tls,
		"Q": http,
		"A": "https://www.example.com:" + tls,
		"S": "https://api.example.com:" + tls,
		"X": "https://www.example.net:" + tls,
		"C": "https://u:p@www.example.net:" + tls,
		"U": "https://u:p@www.example.com:" + tls,
		"W": "https://u:x@www.example.com:" + tls,
		"H": "http://www.example.com:" + http,
		"L": "http://localhost:" + http,
		"D": "http://app.localhost:" + http,
		"4": "http://127.0.0.1:" + http,
		"6": "http://[::1]:" + http,
	}
}

// fill is text with the origins and the scenario's name in place.
func fill(text, id string, o map[string]string) string {
	for k, v := range o {
		text = strings.ReplaceAll(text, "{"+k+"}", v)
	}
	return strings.ReplaceAll(text, "{ID}", id)
}

// plan is what a run of a scenario opens and waits for.
type plan struct {
	start, wait, pre string
	times            int
	settle           time.Duration
}

// planned is the scenario id, as run over o.
func (s scenario) planned(id string, o map[string]string) plan {
	start, wait := s.start, s.wait
	if start == "" {
		start = "{A}/run/{ID}"
	}
	if wait == "" {
		wait = "/done/{ID}"
	}
	return plan{start: fill(start, id, o), wait: fill(wait, id, o), pre: fill(s.pre, id, o), times: max(s.times, 1),
		settle: s.settle}
}
