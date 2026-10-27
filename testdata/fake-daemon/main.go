// Command fake-daemon is the native test transport used where shell-script
// wrappers are not executable, most notably on Windows. It deliberately lives
// under testdata so `go test ./...` and release builds ignore it.
//
// Its scenarios are the ones testdata/fake-daemon/scenarios.json names, and
// every fake answers the same ones: see that file.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type request struct {
	ID           int               `json:"id"`
	Method       string            `json:"method"`
	URL          string            `json:"url"`
	Headers      map[string]string `json:"headers"`
	Order        []string          `json:"order"`
	SetCookie    []string          `json:"setCookie"`
	Body         *string           `json:"body"`
	BodyEncoding string            `json:"bodyEncoding"`
	Control      *string           `json:"control"`
	Proxy        *string           `json:"proxy"`
	Browser      json.RawMessage   `json:"browser"`

	// sent are the names of the fields the line had.
	sent []string
}

var outputMu sync.Mutex

// How many control lines and requests this process has read: what a client
// sent, which a test of what it did not send reads back.
var controls, requests int

// proxy is the proxy the init line named, for a fake started with
// --proxy-stdin, and nil until then.
var proxy any

func main() {
	// A copy named where.exe is used by the Node resolver tests. Keeping this in
	// the same native helper avoids skipping PATH edge cases on Windows merely
	// because a shell script cannot stand in for where.exe there.
	switch os.Getenv("TLSFORGE_TEST_FINDER") {
	case "missing":
		_, _ = fmt.Fprint(os.Stdout, "C:\\definitely\\not\\here.exe\r\n")
		return
	case "empty":
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "--sleep" {
		time.Sleep(30 * time.Second)
		return
	}

	// A tls-forge older than the client, which does not know --proxy-stdin and
	// refuses to start as pflag does, with code 2; or one that refuses whatever
	// it is started with.
	proxyStdin := slices.Contains(os.Args[1:], "--proxy-stdin")
	if refuse := os.Getenv("TLSFORGE_TEST_REFUSE"); refuse == "always" || (refuse == "proxy-stdin" && proxyStdin) {
		_, _ = fmt.Fprintln(os.Stderr, "tlsforge: bad usage: unknown flag: --proxy-stdin")
		os.Exit(2)
	}

	if proxyStdin && os.Getenv("TLSFORGE_TEST_INIT") == "deaf" {
		inits["deaf"](request{})
		return
	}

	// Reads nothing, for as long as it is told, and then is gone: a write
	// larger than the pipe holds waits on it all that time. Before its init
	// line where it waits for one; else once it has answered hello, which
	// the SDKs ask before any request, as the Python fake does.
	if proxyStdin {
		deafFor()
	}

	scanner := bufio.NewScanner(os.Stdin)
	// As much as the daemon reads, and more: a client's refusal of a longer
	// request is what is under test, not this fake's.
	scanner.Buffer(make([]byte, 64*1024), 32*1024*1024)
	initialised := !proxyStdin
	for scanner.Scan() {
		if file := os.Getenv("TLSFORGE_TEST_WIRE_LOG"); file != "" {
			out, err := os.OpenFile(file, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				panic(err)
			}
			_, _ = out.Write(append(append([]byte(nil), scanner.Bytes()...), '\n'))
			_ = out.Close()
		}
		var req request
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			emit(map[string]any{"id": 0, "error": "bad request"})
			continue
		}
		_ = json.Unmarshal(scanner.Bytes(), &fields)
		req.sent = slices.Sorted(maps.Keys(fields))
		if !initialised {
			if req.Control == nil || *req.Control != "init" {
				emit(blank(req, map[string]any{"error": "the first line is not the init line"}))
				os.Exit(1)
			}
			initialised = true
			initLine(req)
			continue
		}
		if req.Control != nil {
			controls++
			control(req)
			continue
		}
		requests++

		parsed, _ := url.Parse(req.URL)
		scenario, known := scenarios[parsed.Hostname()]
		if !known {
			emit(map[string]any{"id": req.ID, "error": fmt.Sprintf("unknown scenario %q", parsed.Hostname())})
			continue
		}
		scenario(req)
	}
}

// password is the password of a proxy URL, as the init line's answer leaves
// it out.
var password = regexp.MustCompile(`:[^:@/]*@`)

// inits are what the init line is answered with, by TLSFORGE_TEST_INIT, for
// a fake started with --proxy-stdin, which reads it first: without an error
// when it says nothing. "deaf" is the one acted on before the line is read.
var inits = map[string]func(request){
	"": func(req request) { emit(blank(req, nil)) },
	"refuse": func(req request) {
		said := ""
		if req.Proxy != nil {
			said = *req.Proxy
		}
		if at := password.FindStringIndex(said); at != nil {
			said = said[:at[0]] + ":***@" + said[at[1]:]
		}
		emit(blank(req, map[string]any{"error": fmt.Sprintf("the init line's proxy %s is no proxy", said)}))
		os.Exit(1)
	},
	"silent":  func(request) {},
	"exit":    func(request) { os.Exit(3) },
	"garbage": func(request) { raw("not json at all\n") },
	// Closes its input before anything has read from it, and stays: the
	// client's write of the init line finds a pipe nobody can read.
	"deaf": func(request) {
		_ = os.Stdin.Close()
		time.Sleep(30 * time.Second)
	},
}

// initLine answers the init line as TLSFORGE_TEST_INIT says, keeping the
// proxy it names.
func initLine(req request) {
	if req.Proxy != nil {
		proxy = *req.Proxy
	}
	mode := os.Getenv("TLSFORGE_TEST_INIT")
	answerInit, known := inits[mode]
	if !known {
		emit(blank(req, map[string]any{"error": fmt.Sprintf("unknown init mode %q", mode)}))
		return
	}
	answerInit(req)
}

// with is answer laid over with extra.
func with(req request, extra map[string]any) map[string]any {
	response := answer(req)
	for name, value := range extra {
		response[name] = value
	}
	return response
}

// replay is a committed answer, with the request's id: the wire format the
// clients are held to, replayed. See testdata/protocol/README.md.
func replay(req request, name string) map[string]any {
	var response map[string]any
	data, err := os.ReadFile(filepath.Join(os.Getenv("TLSFORGE_PROTOCOL_FIXTURES"), name))
	if err == nil {
		err = json.Unmarshal(data, &response)
	}
	if err != nil {
		return map[string]any{"id": req.ID, "error": err.Error()}
	}
	response["id"] = req.ID
	return response
}

// scenarios are what a request is answered with, by the host of its URL. Keep
// them what scenarios.json says, and what the Python and Node fakes do: this
// one is what both suites run on Windows.
var scenarios = map[string]func(request){
	"ok":    func(req request) { emit(answer(req)) },
	"error": func(req request) { emit(map[string]any{"id": req.ID, "error": "upstream refused"}) },
	// What the transport really sends when a request fails: the shape is whole.
	"null-fields": func(req request) {
		emit(map[string]any{"id": req.ID, "status": 0, "url": "", "body": "", "headers": nil, "cookies": nil})
	},
	"null-values": func(req request) {
		emit(with(req, map[string]any{"status": nil, "url": nil, "body": nil, "headers": nil, "cookies": nil}))
	},
	"bad-error":  func(req request) { emit(with(req, map[string]any{"error": map[string]any{}})) },
	"bad-status": func(req request) { emit(with(req, map[string]any{"status": "200"})) },
	"bad-url":    func(req request) { emit(with(req, map[string]any{"url": 7})) },
	"bad-body":   func(req request) { emit(with(req, map[string]any{"body": []any{}})) },
	// PNG magic followed by a byte that cannot be represented as UTF-8.
	"binary": func(req request) {
		raw := []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xff}
		emit(with(req, map[string]any{"body": base64.StdEncoding.EncodeToString(raw), "bodyEncoding": "base64"}))
	},
	// Hands back what it was sent, so the request direction can be checked.
	"echo-body": func(req request) {
		body := ""
		if req.Body != nil {
			body = *req.Body
		}
		emit(with(req, map[string]any{"body": body, "bodyEncoding": req.BodyEncoding}))
	},
	"utf8-encoding": func(req request) {
		emit(with(req, map[string]any{"body": "plain text", "bodyEncoding": "utf8"}))
	},
	"bad-body-encoding": func(req request) {
		emit(with(req, map[string]any{"body": "x", "bodyEncoding": "rot13"}))
	},
	"bad-body-encoding-type": func(req request) {
		emit(with(req, map[string]any{"body": "x", "bodyEncoding": 7}))
	},
	"bad-base64": func(req request) {
		emit(with(req, map[string]any{"body": "!!not base64!!", "bodyEncoding": "base64"}))
	},
	"bad-headers":       func(req request) { emit(with(req, map[string]any{"headers": []any{}})) },
	"bad-header-scalar": func(req request) { emit(with(req, map[string]any{"headers": map[string]any{"broken": 7}})) },
	"bad-header-list": func(req request) {
		emit(with(req, map[string]any{"headers": map[string]any{"broken": []any{7}}}))
	},
	"bad-cookies":     func(req request) { emit(with(req, map[string]any{"cookies": map[string]any{}})) },
	"bad-cookie-item": func(req request) { emit(with(req, map[string]any{"cookies": []any{7}})) },
	"legacy-headers": func(req request) {
		emit(with(req, map[string]any{"headers": map[string]string{"content-type": "application/json"}}))
	},
	"newer-fields":  func(req request) { emit(with(req, map[string]any{"teleport": true})) },
	"null-headers":  func(req request) { emit(with(req, map[string]any{"headers": nil})) },
	"fixture":       func(req request) { emit(replay(req, "response.json")) },
	"fixture-text":  func(req request) { emit(replay(req, "response-text.json")) },
	"fixture-error": func(req request) { emit(replay(req, "response-error.json")) },
	"garbage":       func(request) { raw("not json at all\n") },
	"null-line":     func(request) { raw("null\n") },
	"no-id": func(req request) {
		emit(map[string]any{"status": 200, "body": "anonymous"})
		after(50*time.Millisecond, func() { emit(answer(req)) })
	},
	"wrong-id": func(req request) {
		emit(map[string]any{"id": req.ID + 1000, "status": 200, "body": "stray"})
		after(50*time.Millisecond, func() { emit(answer(req)) })
	},
	"trailing-lines": func(req request) {
		emit(answer(req))
		after(10*time.Millisecond, func() {
			raw("not json at all\n")
			emit(map[string]any{"status": 200, "body": "orphan"})
		})
	},
	// The client's deadline is the only thing that ends this request.
	"silent": func(request) {},
	"slow":   func(req request) { after(400*time.Millisecond, func() { emit(answer(req)) }) },
	"exit":   func(request) { os.Exit(3) },
	// Answers, and dies while nobody is asking it anything.
	"answer-then-exit": func(req request) {
		emit(answer(req))
		after(50*time.Millisecond, func() { os.Exit(4) })
	},
	// Never answers, and reads nothing more: the end of its input is not
	// noticed, and it has to be stopped.
	"stubborn": func(request) { time.Sleep(30 * time.Second) },
	// Answers, and keeps running after closing the read side: the client sees
	// a dead pipe rather than a process exit on its next write.
	"deaf": func(req request) {
		emit(answer(req))
		_ = os.Stdin.Close()
		time.Sleep(30 * time.Second)
	},
	"stderr": func(req request) {
		_, _ = fmt.Fprintln(os.Stderr, "a note on stderr")
		time.Sleep(50 * time.Millisecond)
		emit(answer(req))
	},
	"stderr-chunks": func(req request) {
		_, _ = fmt.Fprint(os.Stderr, "one logical")
		time.Sleep(5 * time.Millisecond)
		_, _ = fmt.Fprint(os.Stderr, " line\nsecond line\n")
		emit(answer(req))
	},
}

// blank is the answer to a control line, with extra laid over it.
func blank(req request, extra map[string]any) map[string]any {
	out := map[string]any{"id": req.ID, "status": 0, "url": "", "body": "", "headers": nil, "cookies": nil}
	for name, value := range extra {
		out[name] = value
	}
	return out
}

// protocols are what hello is answered with, by TLSFORGE_TEST_PROTOCOL:
// protocol 2 with TLSFORGE_TEST_CAPABILITIES when it says nothing.
var protocols = map[string]func(request){
	"": func(req request) {
		extra := map[string]any{"protocol": 3, "engine_major": 1, "version": "1.0.0"}
		if raw, ok := os.LookupEnv("TLSFORGE_TEST_ENGINE_MAJOR"); ok {
			if raw == "missing" {
				delete(extra, "engine_major")
			} else {
				var major any
				if err := json.Unmarshal([]byte(raw), &major); err != nil {
					panic(err)
				}
				extra["engine_major"] = major
			}
		}
		if version, ok := os.LookupEnv("TLSFORGE_TEST_ENGINE_VERSION"); ok {
			extra["version"] = version
		}
		if names := strings.Split(os.Getenv("TLSFORGE_TEST_CAPABILITIES"), ","); names[0] != "" {
			extra["capabilities"] = slices.DeleteFunc(names, func(name string) bool { return name == "" })
		}
		emit(blank(req, extra))
		deafFor()
	},
	"1":           func(req request) { emit(blank(req, map[string]any{"error": "bad request: no url"})) },
	"fixture":     func(req request) { emit(replay(req, "response-hello.json")) },
	"fixture-old": func(req request) { emit(replay(req, "response-hello-old.json")) },
	"bad":         func(req request) { emit(blank(req, map[string]any{"protocol": "two"})) },
	"bool":        func(req request) { emit(blank(req, map[string]any{"protocol": true})) },
	"bad-capabilities": func(req request) {
		emit(blank(req, map[string]any{"protocol": 2, "capabilities": []any{7}}))
	},
	"no-capabilities": func(req request) {
		emit(blank(req, map[string]any{"protocol": 2, "capabilities": "all"}))
	},
	"low": func(req request) { emit(blank(req, map[string]any{"protocol": 1})) },
	"newer": func(req request) {
		emit(blank(req, map[string]any{"protocol": 7, "engine_major": 1, "version": "1.0.0", "capabilities": []string{"browser_context", "teleport"}}))
	},
	"silent": func(request) {},
	"exit":   func(request) { os.Exit(3) },
}

// control answers a control line: "scenarios" with what this fake answers,
// for the suite that holds it to scenarios.json, and hello as
// TLSFORGE_TEST_PROTOCOL says.
func control(req request) {
	if *req.Control == "scenarios" {
		emit(map[string]any{
			"id": req.ID, "requests": slices.Sorted(maps.Keys(scenarios)),
			"protocols": slices.Sorted(maps.Keys(protocols)), "inits": slices.Sorted(maps.Keys(inits)),
		})
		return
	}
	mode := os.Getenv("TLSFORGE_TEST_PROTOCOL")
	answerHello, known := protocols[mode]
	if !known {
		emit(blank(req, map[string]any{"error": fmt.Sprintf("unknown protocol mode %q", mode)}))
		return
	}
	answerHello(req)
}

func answer(req request) map[string]any {
	headers := req.Headers
	if headers == nil {
		headers = map[string]string{}
	}
	order := req.Order
	if order == nil {
		order = []string{}
	}
	cookies := req.SetCookie
	if cookies == nil {
		cookies = []string{}
	}

	env := map[string]any{}
	for _, name := range []string{"TLSFORGE_PROXY", "SSLKEYLOGFILE", "sslkeylogfile", "QUIC_GO_DISABLE_ECN", "QUIC_GO_DISABLE_GSO", "QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "QUIC_GO_LOG_LEVEL", "QUIC_GO_DISABLE_CLIENTHELLO_SCRAMBLING", "GODEBUG"} {
		env[name] = nil
		if inherited, set := os.LookupEnv(name); set {
			env[name] = inherited
		}
	}

	// In characters, as the Python and Node fakes count a string: a body of
	// "я" is one long, not two.
	bodyLength := 0
	if req.Body != nil {
		bodyLength = utf8.RuneCountInString(*req.Body)
	}
	var browser any
	_ = json.Unmarshal(req.Browser, &browser)
	body, _ := json.Marshal(map[string]any{
		"argv": os.Args[1:], "env": env, "proxy": proxy, "pid": os.Getpid(), "bodyLength": bodyLength,
		"method": req.Method, "headers": headers,
		"order": order, "cookies": cookies, "body": req.Body,
		"browser": browser, "sent": req.sent, "controls": controls, "requests": requests,
	})
	return map[string]any{
		"id": req.ID, "status": 200, "url": req.URL, "body": string(body),
		"headers": map[string][]string{
			"content-type": {"application/json"},
			"set-cookie":   {"a=1", "b=2"},
		},
		"cookies": []string{},
	}
}

// deafFor reads nothing for TLSFORGE_TEST_DEAF_FOR seconds, when it is set,
// and then ends the fake.
func deafFor() {
	if deaf, err := time.ParseDuration(os.Getenv("TLSFORGE_TEST_DEAF_FOR") + "s"); err == nil && deaf > 0 {
		time.Sleep(deaf)
		os.Exit(0)
	}
}

func emit(value any) {
	outputMu.Lock()
	defer outputMu.Unlock()
	_ = json.NewEncoder(os.Stdout).Encode(value)
}

func raw(value string) {
	outputMu.Lock()
	defer outputMu.Unlock()
	_, _ = fmt.Fprint(os.Stdout, value)
}

func after(delay time.Duration, fn func()) {
	time.AfterFunc(delay, fn)
}
