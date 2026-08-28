package echo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"
)

// selfSignedCert mints a throwaway certificate for the loopback interface.
//
// A generated certificate rather than a checked-in one: a private key in a
// public repository is a private key on every machine that clones it, and the
// temptation to reuse "the test key" somewhere real is exactly how those end up
// in production. It costs a few milliseconds at startup.
//
// Clients must be told to accept it — the browser is launched with certificate
// errors ignored, and the library's own client sets InsecureSkipVerify for this
// host only. That is safe here in a way it never is in general: the server is on
// loopback, it is this process, and nothing secret crosses it.
// The crypto hooks are named so tests can make each operation fail without
// depending on how many bytes a particular Go release reads from its entropy
// source. Those failures decide whether the server starts at all.
var (
	randReader        io.Reader = rand.Reader
	generateKey                 = ecdsa.GenerateKey
	randomInt                   = rand.Int
	createCertificate           = x509.CreateCertificate
)

func selfSignedCert(hosts []string) (tls.Certificate, error) {
	key, err := generateKey(elliptic.P256(), randReader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("echo: generate key: %w", err)
	}
	serial, err := randomInt(randReader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("echo: serial: %w", err)
	}

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "tlsforge echo"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
			continue
		}
		template.DNSNames = append(template.DNSNames, h)
	}

	der, err := createCertificate(randReader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("echo: create certificate: %w", err)
	}
	// Leaf is left unset: crypto/tls parses it when it needs it, and re-parsing
	// DER that x509 has just produced can only fail in ways that would mean the
	// standard library disagreed with itself.
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
