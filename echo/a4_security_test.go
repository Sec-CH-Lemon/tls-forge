package echo

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestNavigationTokensRejectOtherVisitors(t *testing.T) {
	s := startServer(t, WithManual(true))
	owner := &Session{remote: "192.0.2.1:1000"}
	token, err := s.setNavigation(owner, "", visitorOf(owner, nil))
	if err != nil {
		t.Fatal(err)
	}
	if raw, err := hex.DecodeString(token); err != nil || len(raw) != 16 {
		t.Errorf("token is not random 128-bit hex: %q", token)
	}
	s.awaitHTTP1(visitorOf(owner, nil), owner)
	for _, path := range []string{"/skip", "/collect", "/hello?step=tickets", "/hello?step=resumed"} {
		separator := "?"
		if strings.Contains(path, "?") {
			separator = "&"
		}
		req := &request{path: path + separator + "navigation=" + token, body: []byte(`{"user_agent":"poisoned"}`)}
		s.tickets = map[string]int64{"192.0.2.1": 42, "192.0.2.2": 43}
		status, _, _ := s.route(&Session{remote: "192.0.2.2:1000"}, req)
		if status != "400" || req.completes != nil || owner.navigator != nil || len(s.tickets) != 2 || s.tickets["192.0.2.1"] != 42 || s.tickets["192.0.2.2"] != 43 {
			t.Errorf("foreign %s: status=%s completed=%v navigator=%v tickets=%v", path, status, req.completes, owner.navigator, s.tickets)
		}
	}
	if got, err := s.captureSession(token, &Session{remote: "192.0.2.2:1000"}, "192.0.2.2\n"); err == nil {
		t.Errorf("foreign direct report accepted: %v", got)
	}
	req := &request{path: "/skip?navigation=" + token}
	if status, _, _ := s.route(&Session{remote: "192.0.2.1:2000"}, req); status != "200" || req.completes != owner {
		t.Errorf("owner on a new connection rejected: %s", status)
	}
}

func TestNavigationVisitorChecksEveryAttachment(t *testing.T) {
	s := startServer(t)
	owner := &Session{remote: "192.0.2.1:1000"}
	visitor := visitorOf(owner, map[string]string{"user-agent": "owner"})
	token, err := s.setNavigation(owner, "", visitor)
	if err != nil {
		t.Fatal(err)
	}
	for _, foreign := range []string{"192.0.2.2\nowner", "192.0.2.1\nother"} {
		if _, err := s.setNavigation(owner, token, foreign); err == nil {
			t.Error("foreign page accepted")
		}
		if _, err := s.setNavigation(owner, "", foreign); err == nil {
			t.Error("changed visitor on existing connection accepted")
		}
		if err := s.attachHTTP1(token, nil, foreign); err == nil {
			t.Error("foreign HTTP1 accepted")
		}
	}
	if err := s.attachHTTP1(token, nil, visitor); err != nil {
		t.Fatal(err)
	}
	if _, err := s.setNavigation(owner, "guessed", visitor); err == nil {
		t.Error("existing page bypassed invalid token")
	}
	seen := map[string]bool{token: true}
	for range 100 {
		next, err := s.setNavigation(&Session{}, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if seen[next] {
			t.Fatalf("repeated navigation token %q", next)
		}
		seen[next] = true
	}
}
