package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/proxy"
)

func runProxy(ctx context.Context, args []string, out, errOut *printer) error {
	fs := newFlagSet("proxy", out)
	common := addClientFlags(fs)
	addr := fs.StringP("addr", "a", "127.0.0.1:8080", "listen address")
	certFile := fs.String("ca-cert", "",
		"certificate authority to sign with (default: alongside the config)")
	keyFile := fs.String("ca-key", "", "the authority's key")
	quiet := fs.BoolP("quiet", "q", false, "do not report per-connection failures")
	if err := parse(fs, args); err != nil {
		return err
	}

	defaultCert, defaultKey, err := defaultCAPaths()
	if err != nil {
		return err
	}
	if *certFile == "" {
		*certFile = defaultCert
	}
	if *keyFile == "" {
		*keyFile = defaultKey
	}

	ca, err := proxy.LoadOrCreateCA(*certFile, *keyFile)
	if err != nil {
		return err
	}

	// No cookie jar: the caller's `Cookie` header is forwarded as sent, and a
	// jar underneath would add a second one from its own store, leaving the
	// caller's session and the proxy's quietly diverging.
	client, err := common.client(tlsforge.WithoutCookieJar())
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	// Per-connection trouble is commentary, and stdout here is a running log
	// somebody may be piping.
	onError := func(err error) { errOut.println("  " + err.Error()) }
	if *quiet {
		onError = func(error) {}
	}

	server, err := proxy.Start(proxy.Options{
		Addr: *addr, CA: ca, Client: client, OnError: onError,
	})
	if err != nil {
		return err
	}
	defer func() { _ = server.Close() }()

	out.printf("proxy listening on %s\n\n", server.Addr())
	out.printf("  export HTTPS_PROXY=http://%s\n", server.Addr())
	// browserleaks answers with the JA4 it saw, so the suggested command is not
	// just a smoke test: its output is the proof the handshake was replaced.
	out.printf("  curl --proxy http://%s --cacert %s https://tls.browserleaks.com/json\n\n",
		server.Addr(), shellQuote(*certFile))
	out.println("The proxy terminates TLS itself, which is the only way to replace the")
	out.println("handshake: a tunnelled CONNECT would carry your own client's fingerprint")
	out.println("straight through. So clients have to trust the authority above.")
	out.println()
	out.println("That authority can impersonate any site to anything that trusts it. Prefer")
	out.printf("--cacert over installing it system-wide, and delete %s when done.\n", shellQuote(*keyFile))
	out.println()
	out.println("Ctrl-C to stop.")

	<-ctx.Done()
	return nil
}

// defaultCAPaths puts the authority under the user's config directory rather
// than the working directory, so that a key with this much power does not end
// up committed by whoever runs the proxy inside a repository.
func defaultCAPaths() (certFile, keyFile string, err error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", "", fmt.Errorf("tlsforge: no config directory: %w", err)
	}
	dir = filepath.Join(dir, "tls-forge")
	return filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"), nil
}
