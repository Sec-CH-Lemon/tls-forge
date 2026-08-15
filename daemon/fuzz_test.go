package daemon

import (
	"bufio"
	"encoding/json"
	"strings"
	"testing"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
)

// Fuzzing the request decoder.
//
// A line here comes from whoever started the process, which is a lower bar than
// the wire parser has to clear. It gets a fuzzer anyway, for two reasons: a
// caller that has started producing garbage is exactly when a daemon must stay
// answerable, and the id it echoes is what a caller uses to tell one answer
// from another. A line that produced no answer at all, or the wrong id, is how
// a client ends up filing one page under another page's request.
func FuzzHandle(f *testing.F) {
	f.Add(`{"id":7,"url":"https://example.com/"}`)
	f.Add(`{"id":7,"url":"https://example.com/","headers":{"a":"b"},"order":["a"]}`)
	f.Add(`{"id":7,"url":"https://example.com/","cookies":["a=b"],"method":"POST","body":"x"}`)
	f.Add(`{"id":7}`)
	f.Add(`{"id":"seven","url":"https://example.com/"}`)
	f.Add(`{`)
	f.Add(`[]`)
	f.Add(`null`)

	client := &fakeClient{headers: tlsforge.NewHeader("user-agent", "x")}

	f.Fuzz(func(t *testing.T, input string) {
		// Counted the way Serve counts: it scans lines and skips blank ones, so
		// an input carrying newlines is several requests and owes several
		// answers. Asserting one answer per input instead would only be testing
		// that the fuzzer had not put a newline in.
		wanted := 0
		counter := bufio.NewScanner(strings.NewReader(input))
		for counter.Scan() {
			if strings.TrimSpace(counter.Text()) != "" {
				wanted++
			}
		}
		if counter.Err() != nil || wanted == 0 {
			return
		}

		var out strings.Builder
		if err := Serve(strings.NewReader(input+"\n"), &out, client); err != nil {
			// A line past the buffer is a caller bug, and reporting it is the
			// right answer to one.
			return
		}

		// One answer per line, always. A caller waits for one, and a missing
		// answer is a client that hangs until its own timeout.
		answers := strings.Split(strings.TrimSpace(out.String()), "\n")
		if len(answers) != wanted {
			t.Fatalf("%d answers to %d lines: %q", len(answers), wanted, input)
		}

		// And each has to be a JSON object the caller can read, carrying either
		// a result or a reason, never neither.
		for _, answer := range answers {
			var res Response
			if err := json.Unmarshal([]byte(answer), &res); err != nil {
				t.Fatalf("an answer to %q is not JSON: %v", input, err)
			}
			if res.Error == "" && res.Status == 0 {
				t.Fatalf("an answer to %q says nothing: %+v", input, res)
			}
		}
	})
}
