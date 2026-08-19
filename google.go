package tlsforge

import (
	"net/url"
	"strings"
)

// What Chrome tells Google, and tells nobody else.
//
// On a request to a Google property Chrome adds a block of headers no other
// origin ever sees:
//
//	x-browser-channel      stable
//	x-browser-year         2026
//	x-browser-validation   iix1/iDR1W9e3SUCZHWKwrVpus8=
//	x-browser-copyright    Copyright 2026 Google LLC. All Rights Reserved.
//	x-client-data          CJzjygE=
//
// Measured rather than transcribed: this library's own echo server was given the
// name www.google.com, a browser was told that name resolves to loopback, and
// the block above came back in exactly that order, sitting between `accept` and
// `sec-fetch-site`. The same browser against the same server under the name
// `localhost` sent none of it.
//
// Which makes it a fingerprint in the plainest sense. A client that scrapes
// Google carrying the header list of an ordinary site is announcing, in its
// first request, that it is not the browser it just spent a TLS handshake
// claiming to be — and no amount of work on the handshake fixes a missing
// header.
//
// The block is carried in the profile as a second header list rather than as
// five headers to splice in, so replaying it is replaying an order that was
// observed rather than one that was reconstructed.

// googleSuffixes are the registrable domains, outside Google's own search
// domains, measured to receive the block: any host at or under them.
var googleSuffixes = []string{"youtube.com", "ytimg.com", "gstatic.com"}

// googleTLDs is what follows "google." on a host Chrome hands the block to,
// measured one host at a time rather than transcribed.
//
// The list is not derivable. google.io and google.org receive the block;
// google.ai and google.dev, equally Google's, receive nothing — so no rule about
// country codes or about who owns the name reproduces it, and the only honest
// version is the measurement.
//
// Taken by serving one page carrying an image for each of 2,041 candidate hosts,
// with every name resolved to a local server, and recording which ones arrived
// carrying x-browser-channel. 261 did.
var googleTLDs = words(`
ac ad ae af ag al am as at aw az ba be bf bg bi bj bm bn bo bs bt by ca cc
cd cf cg ch ci cl cm cn co co.ao co.bw co.ck co.cr co.gy co.hu co.id co.il
co.im co.in co.je co.jp co.ke co.kr co.ls co.ma co.mz co.nz co.rs co.th
co.tz co.ug co.uk co.uz co.ve co.vi co.za co.zm co.zw com com.af com.ag
com.ai com.ar com.au com.bd com.bh com.bi com.bn com.bo com.br com.by
com.bz com.cn com.co com.cu com.cy com.do com.dz com.ec com.eg com.er
com.et com.fj com.ge com.gh com.gi com.gp com.gr com.gt com.gy com.hk
com.ht com.iq com.jm com.jo com.kh com.kw com.kz com.lb com.lv com.ly
com.mm com.mt com.mx com.my com.na com.nf com.ng com.ni com.np com.nr
com.om com.pa com.pe com.pg com.ph com.pk com.pl com.pr com.ps com.pt
com.py com.qa com.sa com.sb com.sg com.sl com.sv com.tj com.tm com.tn
com.tr com.tw com.ua com.uy com.vc com.ve com.vn cv cz de dj dk dm do dz
ec ee es eu fi fm fr ga gd ge gf gg gl gm gp gr gw gy hk hn hr ht hu ie im
in info io iq is it je jo jp kg ki km kr kz la li lk lt lu lv ma md me mg
mh mk ml mn mr ms mu mv mw mx ne net ng nl no nr nu org pf ph pk pl pn ps
pt qa re ro rs ru rw sc se sg sh si sk sl sm sn so sr st sz td tg tk tl tm
tn to tt tw ua us uz vg vn vu ws yt
`)

// words turns a whitespace-separated block into a set, which keeps the list
// above readable as the list it is.
func words(list string) map[string]bool {
	out := map[string]bool{}
	for _, w := range strings.Fields(list) {
		out[w] = true
	}
	return out
}

// isGoogleHost reports a host Chrome treats as Google's own.
//
// The list is what was measured, one host at a time, by resolving each to a
// local server and asking it for a page. It sent the block to google.com,
// www.google.com, images.google.com, cloud.google.com, accounts.google.com,
// mail.google.com, docs.google.com, news.google.com, google.de, google.ru,
// google.co.uk, google.co.jp, youtube.com, i.ytimg.com and www.gstatic.com. It
// sent nothing to example.com, youtu.be, blogger.com, android.com, google.dev or
// googleusercontent.com.
//
// Owning the name google is not enough, which is the trap here: google.dev and
// google.ai are Google's and receive nothing, while google.io and google.org do.
// What receives the block is the SEARCH domain, and which names those are is a
// list inside Chrome rather than a rule — so googleTLDs holds the measured list.
//
// One measured positive is deliberately left out: www.googleapis.com receives
// the block while bare googleapis.com does not. A rule covering that pair would
// have to be invented rather than observed, and an invented rule is how a list
// that describes a measurement turns into one that describes a guess. Nothing
// scrapes googleapis.com wearing a browser anyway.
func isGoogleHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, suffix := range googleSuffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}

	// Any subdomain of a Google search domain counts — news.google.com and
	// images.google.co.uk were both measured to receive it — so this looks for
	// the "google" label rather than for the start of the host. Matching a label
	// rather than a substring is what keeps google.com.evil.com out.
	labels := strings.Split(host, ".")
	for i, label := range labels {
		if label == "google" && googleTLDs[strings.Join(labels[i+1:], ".")] {
			return true
		}
	}
	return false
}

// headersFor picks the header list for a destination: the Google one when the
// profile carries it and the host is Google's, the ordinary one otherwise.
func (c *Client) headersFor(u *url.URL) Header {
	if len(c.googleHeaders) == 0 || u == nil || !isGoogleHost(u.Hostname()) {
		return c.headers
	}
	return c.googleHeaders
}

// validationHeader is the one header in the block that is derived rather than
// constant.
const validationHeader = "x-browser-validation"

// withoutStaleValidation drops x-browser-validation from a request not carrying
// the user-agent it was computed from.
//
// The value is a function of the user-agent: the same browser sending
// `HeadlessChrome/151.0.0.0` and `Chrome/151.0.0.0` produced two different
// tokens, reproducibly, and either one reproduced exactly on a second run with a
// fresh browser profile. So it survives being replayed — but only alongside the
// user-agent it was measured with.
//
// Overriding the user-agent and keeping the token would send a value the
// receiver can recompute and find wrong, which is worse than not sending it:
// absent is unusual, contradictory is decisive.
func withoutStaleValidation(h Header, capturedUA string) Header {
	if !h.Has(validationHeader) || h.Get("user-agent") == capturedUA {
		return h
	}
	out := h.Clone()
	out.Del(validationHeader)
	return out
}
