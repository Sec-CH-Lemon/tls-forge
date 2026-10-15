package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
)

// Where a run comes out.
//
// A process cannot see its own public address, and through a proxy the address
// is the proxy's, so somebody outside has to be asked. A run that goes one way
// asks once, before its first request, for the last line of what it says it is
// wearing.
//
// That answers for every request made without a proxy, which all come out
// where the machine does. It answers for no request made through one: it was
// asked on a connection of its own, and a proxy can hand every connection an
// address of its own. Where those came out is what the proxy said when it
// opened each of them, when it said anything.

// egress is where a client's requests come out.
type egress struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
	// Hash is what a proxy that will not say the address calls it instead: its
	// own hash of the address, the same for the same address. Never read from
	// an address service's answer, which is where the two above come from.
	Hash string `json:"-"`
	// By is how the address was found when the proxy did not say it: who was
	// asked, and over what.
	By string `json:"-"`
}

// Known says where it came out is known, by the address or by a proxy's hash
// of it.
func (e egress) Known() bool { return e.IP != "" || e.Hash != "" }

// Shown is where it came out, as the report shows it: the address, or the
// whole of the hash a proxy gave instead.
func (e egress) Shown() string { return either(e.IP, e.Hash) }

// into writes where it came out into a trace event, under the names a trace
// gives it.
func (e egress) into(args traceArgs) {
	if e.IP != "" {
		args["exit_ip"] = e.IP
	}
	if e.Hash != "" {
		args["exit_hash"] = e.Hash
	}
	if country := e.countryCode(); country != "" {
		args["exit_country"] = country
	}
	if e.By != "" {
		args["exit_by"] = e.By
	}
}

// Flag is the country as its flag, or empty when there is no country.
//
// Computed rather than looked up: a flag emoji is the two letters of the ISO
// 3166-1 alpha-2 code written as regional indicator symbols, so this needs no
// table and no geolocation database.
func (e egress) Flag() string {
	var flag []rune
	for _, letter := range e.countryCode() {
		flag = append(flag, 0x1F1E6+(letter-'A'))
	}
	return string(flag)
}

// countryCode is the country as its two capital letters, or empty when the
// answer was not an ISO 3166-1 alpha-2 code.
//
// On its own as well as inside the flag, because a terminal is not a browser:
// the report fetch prints says the letters, which every terminal can draw.
func (e egress) countryCode() string {
	code := strings.ToUpper(strings.TrimSpace(e.Country))
	if len(code) != 2 {
		return ""
	}
	for _, letter := range code {
		if letter < 'A' || letter > 'Z' {
			return ""
		}
	}
	return code
}

// addressService is somewhere to ask what address a request came from.
type addressService struct {
	URL string
	// read takes the address, and the country if there is one, out of an
	// answer. Every service has its own way of saying the same thing.
	read func(body []byte) egress
}

// ipServices are asked in this order, each one only when those before it have
// failed or are taking their time.
//
// Four, run by four different parties, because the point of a second is that
// it does not go down, rate limit or get blocked along with the first.
// Cloudflare's trace page and ipinfo.io also name the country. Amazon's and
// ipify's say the address and nothing else, so an address they report comes
// without one.
//
// A variable so a test can answer for them.
var ipServices = []addressService{
	{URL: "https://www.cloudflare.com/cdn-cgi/trace", read: readTrace},
	{URL: "https://checkip.amazonaws.com", read: readAddress},
	{URL: "https://api.ipify.org?format=json", read: readJSON},
	{URL: "https://ipinfo.io/json", read: readJSON},
}

// name is the service's host, which is what it is called wherever a person
// reads who was asked.
func (s addressService) name() string {
	u, err := url.Parse(s.URL)
	if err != nil || u.Host == "" {
		return s.URL
	}
	return u.Host
}

// askedOf names the services in the order they are asked, for the places that
// say who a question is about to go to. Third parties are named rather than
// contacted quietly.
func askedOf() string {
	names := make([]string, 0, len(ipServices))
	for _, service := range ipServices {
		names = append(names, service.name())
	}
	return strings.Join(names, ", then ")
}

// readTrace reads Cloudflare's trace page, which is one key=value to a line.
func readTrace(body []byte) egress {
	var found egress
	for _, line := range strings.Split(string(body), "\n") {
		key, value, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch key {
		case "ip":
			found.IP = value
		case "loc":
			// XX is how it says it does not know.
			if value != "XX" {
				found.Country = value
			}
		}
	}
	return found
}

// readAddress reads an answer that is the address and nothing else.
func readAddress(body []byte) egress {
	return egress{IP: strings.TrimSpace(string(body))}
}

// readJSON reads an answer that is a JSON object with an "ip" in it, and a
// "country" if the service names one.
func readJSON(body []byte) egress {
	var found egress
	// An answer that is not JSON has no address in it, and that is what gets
	// said about any answer that cannot be used.
	_ = json.Unmarshal(body, &found)
	return found
}

// ask puts the question to one service.
//
// The answer has to be an address before it is believed. It is somebody else's
// text, and fetch prints it on a terminal, which escapes nothing.
func (s addressService) ask(ctx context.Context, client *tlsforge.Client) (egress, error) {
	res, err := client.Do(&tlsforge.Request{Context: ctx, URL: s.URL})
	if err != nil {
		return egress{}, err
	}
	if !res.OK() {
		return egress{}, fmt.Errorf("%s: HTTP %d", s.URL, res.Status)
	}
	found := s.read(res.Body)
	// A zone is refused with everything else that is not an address: it may be
	// any text at all, and nothing a request comes out of has one.
	if addr, err := netip.ParseAddr(found.IP); err != nil || addr.Zone() != "" {
		return egress{}, fmt.Errorf("%s: no address in the answer", s.URL)
	}
	return found, nil
}

// asker builds the client a question to a third party is put through: the
// profile, proxy and timeout of the run's own client, and none of its session.
//
// A client of its own, because a cookie that names no domain is filed against
// every host a client talks to. Asked through the client that fetches the
// pages, "which address do I come out of" arrived at the address service with
// the session cookie attached.
func (f clientFlags) asker(proxy string) (*tlsforge.Client, error) {
	return f.clientViaWarmed(proxy, nil, tlsforge.WithoutCookieJar())
}

// exitLookupWait bounds how long a run waits to learn where it comes out.
//
// The address is commentary. Fetch asks for it before every run, so it does not
// get the request's whole timeout to hold the run up with: on a network that
// drops the question, that would be half a minute added to every fetch.
//
// A variable rather than a constant so a test can lower it.
var exitLookupWait = 5 * time.Second

// lookupExit asks where requests made with these flags, through this proxy,
// come out.
//
// The services are asked in order, and the next one without waiting for the
// last to give up: at once when a service fails, and after its share of the
// wait when it has said nothing yet. Whoever answers first is believed. Giving
// each a turn of its own would be simpler and worse, because a turn short
// enough to reach the fourth service is too short for the first to answer
// through a slow proxy, and a slow proxy is when the address is most wanted.
//
// Normally that is one question to one service. It is more only when the
// first is slow or broken.
func lookupExit(ctx context.Context, flags clientFlags, proxy string) (egress, error) {
	services := ipServices
	if len(services) == 0 {
		return egress{}, errors.New("no address service to ask")
	}
	asker, err := flags.asker(proxy)
	if err != nil {
		return egress{}, err
	}

	ctx, cancel := context.WithTimeout(ctx, exitLookupWait)
	type answer struct {
		from  int
		found egress
		err   error
	}
	// Room for every answer, so a service that answers after the question is
	// settled has somewhere to put it and nobody to wait for.
	answers := make(chan answer, len(services))
	var asking sync.WaitGroup
	ask := func(i int) {
		asking.Add(1)
		go func() {
			defer asking.Done()
			found, err := services[i].ask(ctx, asker)
			answers <- answer{i, found, err}
		}()
	}
	// The client is closed when the last question put through it has ended.
	// That can be after this returns: an answer ends the wait, and so does the
	// time running out, whatever is still on its way.
	defer func() {
		cancel()
		go func() {
			asking.Wait()
			_ = asker.Close()
		}()
	}()

	patience := exitLookupWait / time.Duration(len(services))
	next := time.NewTimer(patience)
	defer next.Stop()

	asked, failed := 0, 0
	askNext := func() {
		if asked < len(services) {
			ask(asked)
			asked++
			next.Reset(patience)
		}
	}
	askNext()

	// When every service has failed, what the first one made of it is what gets
	// reported: it is the one everybody is asked through, and four failures on
	// one line is three too many to read.
	var first error
	for {
		select {
		case a := <-answers:
			if a.err == nil {
				return a.found, nil
			}
			if a.from == 0 {
				first = a.err
			}
			failed++
			if failed == len(services) {
				return egress{}, unanswered(first, asked, len(services))
			}
			askNext()
		case <-next.C:
			askNext()
		case <-ctx.Done():
			// Here rather than left to the questions to notice for themselves:
			// the wait is over when it is over, whatever any of them is in the
			// middle of.
			return egress{}, unanswered(ctx.Err(), asked, len(services))
		}
	}
}

// unanswered is what is said when nobody could say where a run comes out: why,
// and how many services that was asked of.
func unanswered(why error, asked, known int) error {
	if known == 1 {
		return why
	}
	return fmt.Errorf("%w (%d of %d services asked, none answered)", why, asked, known)
}
