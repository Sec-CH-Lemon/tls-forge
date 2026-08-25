// Command fake-daemon is the native test transport used where shell-script
// wrappers are not executable, most notably on Windows. It deliberately lives
// under testdata so `go test ./...` and release builds ignore it.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sync"
	"time"
)

type request struct {
	ID        int               `json:"id"`
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers"`
	Order     []string          `json:"order"`
	SetCookie []string          `json:"setCookie"`
	Body      *string           `json:"body"`
}

var outputMu sync.Mutex

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

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var req request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			emit(map[string]any{"id": 0, "error": "bad request"})
			continue
		}

		parsed, _ := url.Parse(req.URL)
		switch parsed.Hostname() {
		case "ok":
			emit(answer(req))
		case "error":
			emit(map[string]any{"id": req.ID, "error": "upstream refused"})
		case "null-fields":
			emit(map[string]any{
				"id": req.ID, "status": 0, "url": "", "body": "",
				"headers": nil, "cookies": nil,
			})
		// Keep these malformed protocol cases aligned with the Python and Node
		// fixtures: this native version is what both suites run on Windows.
		case "bad-error":
			response := answer(req)
			response["error"] = map[string]any{}
			emit(response)
		case "bad-status":
			response := answer(req)
			response["status"] = "200"
			emit(response)
		case "bad-url":
			response := answer(req)
			response["url"] = 7
			emit(response)
		case "bad-body":
			response := answer(req)
			response["body"] = []any{}
			emit(response)
		case "bad-headers":
			response := answer(req)
			response["headers"] = []any{}
			emit(response)
		case "bad-header-scalar":
			response := answer(req)
			response["headers"] = map[string]any{"broken": 7}
			emit(response)
		case "bad-header-list":
			response := answer(req)
			response["headers"] = map[string]any{"broken": []any{7}}
			emit(response)
		case "bad-cookies":
			response := answer(req)
			response["cookies"] = map[string]any{}
			emit(response)
		case "bad-cookie-item":
			response := answer(req)
			response["cookies"] = []any{7}
			emit(response)
		case "garbage":
			raw("not json at all\n")
		case "null-line":
			raw("null\n")
		case "no-id":
			emit(map[string]any{"status": 200, "body": "anonymous"})
			after(50*time.Millisecond, func() { emit(answer(req)) })
		case "wrong-id":
			emit(map[string]any{"id": req.ID + 1000, "status": 200, "body": "stray"})
			after(50*time.Millisecond, func() { emit(answer(req)) })
		case "silent":
			// The client's deadline is the only thing that ends this request.
		case "slow":
			after(400*time.Millisecond, func() { emit(answer(req)) })
		case "exit":
			os.Exit(3)
		case "stderr":
			_, _ = fmt.Fprintln(os.Stderr, "a note on stderr")
			time.Sleep(50 * time.Millisecond)
			emit(answer(req))
		case "legacy-headers":
			response := answer(req)
			response["headers"] = map[string]string{"content-type": "application/json"}
			emit(response)
		case "null-headers":
			response := answer(req)
			response["headers"] = nil
			emit(response)
		case "trailing-lines":
			emit(answer(req))
			after(10*time.Millisecond, func() {
				raw("not json at all\n")
				emit(map[string]any{"status": 200, "body": "orphan"})
			})
		case "deaf":
			emit(answer(req))
			// Keep running after closing the read side. The client sees a dead
			// pipe rather than a process exit on its next write.
			_ = os.Stdin.Close()
			time.Sleep(30 * time.Second)
			return
		default:
			response := answer(req)
			response["status"] = 404
			emit(response)
		}
	}
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

	body, _ := json.Marshal(map[string]any{
		"argv": os.Args[1:], "method": req.Method, "headers": headers,
		"order": order, "cookies": cookies, "body": req.Body,
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
