package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/daemon"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// headerFlag collects repeated -H "Name: value" flags, in the order given.
//
// A slice rather than a map, and in the order given, because that order is part
// of what this tool exists to control.
type headerFlag tlsforge.Header

func (h *headerFlag) String() string { return "" }

func (h *headerFlag) Set(value string) error {
	name, val, found := strings.Cut(value, ":")
	if !found {
		return fmt.Errorf("expected \"Name: value\", got %q", value)
	}
	*h = append(*h, profile.Field{
		Name:  strings.ToLower(strings.TrimSpace(name)),
		Value: strings.TrimSpace(val),
	})
	return nil
}

// clientFlags are the flags every command that makes requests shares.
type clientFlags struct {
	profile  *string
	proxy    *string
	timeout  *time.Duration
	insecure *bool
}

func addClientFlags(fs interface {
	String(string, string, string) *string
	Duration(string, time.Duration, string) *time.Duration
	Bool(string, bool, string) *bool
}) clientFlags {
	return clientFlags{
		profile:  fs.String("profile", tlsforge.DefaultProfile, "profile to impersonate"),
		proxy:    fs.String("proxy", "", "proxy URL, e.g. http://user:pass@host:port"),
		timeout:  fs.Duration("timeout", tlsforge.Timeout, "request timeout"),
		insecure: fs.Bool("insecure", false, "skip certificate verification"),
	}
}

func (f clientFlags) client() (*tlsforge.Client, error) {
	opts := []tlsforge.Option{
		tlsforge.WithProfile(*f.profile),
		tlsforge.WithTimeout(*f.timeout),
	}
	if *f.proxy != "" {
		opts = append(opts, tlsforge.WithProxy(*f.proxy))
	}
	if *f.insecure {
		opts = append(opts, tlsforge.WithInsecureSkipVerify())
	}
	return tlsforge.New(opts...)
}

func runFetch(_ context.Context, args []string, out *printer) error {
	fs := newFlagSet("fetch", out)
	common := addClientFlags(fs)
	method := fs.String("method", "GET", "HTTP method")
	data := fs.String("data", "", "request body")
	showHeaders := fs.Bool("i", false, "print the status and response headers first")
	output := fs.String("o", "", "write the body to a file instead of stdout")
	var headers headerFlag
	fs.Var(&headers, "H", "extra header, repeatable: -H \"Referer: https://…\"")
	fs.Usage = func() {
		out.println("usage: tls-forge fetch [flags] <url>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("fetch takes exactly one URL")
	}

	client, err := common.client()
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	res, err := client.Do(&tlsforge.Request{
		Method: *method,
		URL:    fs.Arg(0),
		Header: tlsforge.Header(headers),
		Body:   []byte(*data),
	})
	if err != nil {
		return err
	}

	if *showHeaders {
		out.printf("%d %s\n", res.Status, res.URL)
		names := make([]string, 0, len(res.Header))
		for name := range res.Header {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			out.printf("%s: %s\n", name, strings.Join(res.Header[name], "; "))
		}
		out.println()
	}

	if *output != "" {
		if err := os.WriteFile(*output, res.Body, 0o644); err != nil {
			return err
		}
		out.printf("wrote %d bytes to %s\n", len(res.Body), *output)
		return nil
	}
	_, err = out.Write(res.Body)
	return err
}

func runDaemon(_ context.Context, args []string, out *printer) error {
	fs := newFlagSet("daemon", out)
	common := addClientFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	client, err := common.client()
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	// stdin is read directly rather than through the writer the command was
	// given: the protocol is a pipe, and tests substitute it through daemonInput.
	return daemon.Serve(daemonInput, out, client)
}

// daemonInput is os.Stdin, named so a test can supply a script instead.
var daemonInput io.Reader = os.Stdin
