package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// daemonGiven runs the daemon with input as its standard input, and is its
// exit code, each line it answered, and what it said on standard error.
func daemonGiven(t *testing.T, input string, args ...string) (int, []map[string]any, string) {
	t.Helper()
	original := daemonInput
	t.Cleanup(func() { daemonInput = original })
	daemonInput = strings.NewReader(input)
	code, stdout, stderr := exec(t, append([]string{"daemon"}, args...)...)
	var answers []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		if line == "" {
			continue
		}
		var answer map[string]any
		if err := json.Unmarshal([]byte(line), &answer); err != nil {
			t.Fatalf("an answer that is no JSON: %q", line)
		}
		answers = append(answers, answer)
	}
	return code, answers, stderr
}

func TestProxyStdinTakesTheProxyFromTheInitLine(t *testing.T) {
	// The URL comes on the first line of the input, password and all, and
	// goes nowhere else: not the command line, nor the environment.
	server, asked := countingTLS(t)
	var heard []string
	proxy := startProxyHearing(t, func(int, []string) string { return "" })
	proxy.heard = func(fields []string) { heard = append(heard, fields...) }
	input := "\n" + `{"engine_major":1,"id":7,"control":"init","proxy":"http://alice:` + secret + `@` + proxy.addr + `"}` + "\n" +
		`{"engine_major":1,"id":8,"url":"` + server.URL + `"}` + "\n"

	code, answers, stderr := daemonGiven(t, input, "--insecure", "--proxy-stdin")
	if code != 0 || len(answers) != 2 {
		t.Fatalf("exit code = %d, answers %v\n%s", code, answers, stderr)
	}
	if answers[0]["id"] != 7.0 || answers[0]["error"] != nil || answers[0]["status"] != 0.0 {
		t.Errorf("the init line was answered %v", answers[0])
	}
	if answers[1]["id"] != 8.0 || answers[1]["status"] != 200.0 || answers[1]["body"] != "the page" {
		t.Errorf("the request was answered %v", answers[1])
	}
	if !slices.Contains(proxy.seen(), hostOfURL(t, server.URL)) || asked.Load() != 1 {
		t.Errorf("the request did not go through the proxy: %v", proxy.seen())
	}
	credentials := "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("alice:"+secret))
	if !slices.Contains(heard, credentials) {
		t.Errorf("the proxy was not told who was asking: %v", heard)
	}
	if strings.Contains(stderr, secret) {
		t.Errorf("stderr says the proxy's password:\n%s", stderr)
	}
}

func TestProxyStdinRefusals(t *testing.T) {
	// The proxy comes from one place, said before anything is read.
	t.Setenv("RUN_PROXY_SET", "http://alice:"+secret+"@127.0.0.1:1")
	for _, args := range [][]string{
		{"--proxy-stdin", "--proxy", "http://127.0.0.1:2"},
		{"--proxy-env", "RUN_PROXY_SET", "--proxy-stdin"},
	} {
		code, answers, stderr := daemonGiven(t, `{"engine_major":1,"id":1,"control":"init","proxy":"http://127.0.0.1:3"}`+"\n", args...)
		if code != 2 || len(answers) != 0 || !strings.Contains(stderr, "--proxy-stdin takes the proxy from the input") ||
			strings.Contains(stderr, secret) {
			t.Errorf("%q: exit code = %d, answers %v\n%s", args, code, answers, stderr)
		}
	}
}

func TestAnInitLineThatCannotStartTheDaemonIsAnswered(t *testing.T) {
	// With its id, without the password, and nothing sent: the daemon ends
	// with 1, which the packages do not read as a tls-forge older than they.
	server, asked := countingTLS(t)
	request := `{"engine_major":1,"id":5,"url":"` + server.URL + `"}`
	missing := filepath.Join(t.TempDir(), "no-cookies.json")
	for _, tc := range []struct {
		name  string
		input string
		args  []string
		id    float64
		says  string
	}{
		{"a request first", request + "\n", nil, 5, "the first line of a daemon started with --proxy-stdin is its init line"},
		{"an init line with a url", `{"engine_major":1,"id":3,"control":"init","proxy":"http://127.0.0.1:1","url":"` + server.URL + `"}`,
			nil, 3, "is its init line"},
		{"no proxy", `{"engine_major":1,"id":3,"control":"init"}`, nil, 3, "the init line names no proxy"},
		{"no JSON", `{"engine_major":1,"id":3,`, nil, 0, "bad request: unexpected end of JSON input"},
		{"no input", "", nil, 0, "the input ended before the init line"},
		{"nothing but blank lines", "\n \n\t\n", nil, 0, "the input ended before the init line"},
		{"a proxy that is not one", `{"engine_major":1,"id":4,"control":"init","proxy":"http://alice:` + secret + `@[bad"}`, nil, 4,
			"the init line's proxy [redacted]@[bad is not a URL"},
		{"a session file there is none of", `{"engine_major":1,"id":6,"control":"init","proxy":"http://127.0.0.1:1"}`,
			[]string{"--cookies", missing}, 6, "no-cookies.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, answers, stderr := daemonGiven(t, tc.input, append([]string{"--insecure", "--proxy-stdin"}, tc.args...)...)
			if code != 1 || len(answers) != 1 || answers[0]["id"] != tc.id {
				t.Fatalf("exit code = %d, answers %v\n%s", code, answers, stderr)
			}
			said, _ := answers[0]["error"].(string)
			if !strings.Contains(said, tc.says) || strings.Contains(said+stderr, secret) {
				t.Errorf("answered %q\n%s", said, stderr)
			}
		})
	}
	if got := asked.Load(); got != 0 {
		t.Errorf("the server was asked %d times", got)
	}
}

func TestADaemonThatCannotSayItIsReadyEnds(t *testing.T) {
	original := daemonInput
	t.Cleanup(func() { daemonInput = original })
	daemonInput = strings.NewReader(`{"engine_major":1,"id":1,"control":"init","proxy":"http://127.0.0.1:1"}` + "\n")
	var errOut bytes.Buffer
	err := runDaemon(context.Background(), []string{"--proxy-stdin"}, newPrinter(failingWriter{}), newPrinter(&errOut))
	if err == nil || !strings.Contains(err.Error(), "no space left on device") {
		t.Errorf("%v", err)
	}
}

func TestAProfileThereIsNoneOfEndsTheDaemonBeforeItsInitLine(t *testing.T) {
	// With 1, as the packages read a daemon that cannot start, and before it
	// reads its input: the init line goes unanswered.
	original := daemonInput
	t.Cleanup(func() { daemonInput = original })
	line := `{"engine_major":1,"id":1,"control":"init","proxy":"http://127.0.0.1:1"}` + "\n"
	input := strings.NewReader(line)
	daemonInput = input
	code, stdout, stderr := exec(t, "daemon", "--proxy-stdin", "--profile", "netscape_4")
	if code != 1 || stdout != "" || input.Len() != len(line) || !strings.Contains(stderr, "netscape_4") {
		t.Errorf("exit code = %d, stdout %q, %d of %d bytes unread\n%s", code, stdout, input.Len(), len(line), stderr)
	}
}
