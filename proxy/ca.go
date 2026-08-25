package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/internal/atomicfile"
)

// The certificate authority the proxy signs with.
//
// A MITM proxy has to present a certificate for whatever host the client asked
// for, which means minting one per host and signing it with an authority the
// client trusts. There is no way around that: if the client's own TLS reached
// the destination unchanged, the destination would see the client's handshake,
// which is the thing this proxy exists to replace.
//
// The authority is written to disk and reused. A CA regenerated on every start
// would have to be re-trusted on every start, and the natural response to that
// is to stop verifying anything.

// CA is a certificate authority and the leaf certificates it has minted.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

// randReader is the entropy source, named so a test can make it fail. There is
// no other way to reach the error paths of the crypto calls below, and an
// authority that failed to generate is the difference between a proxy that
// starts and one that does not.
var randReader io.Reader = rand.Reader
var chmod = os.Chmod

// How long a generated authority lasts. Long enough not to be a chore, short
// enough that a key left behind on a laptop stops working.
const caLifetime = 365 * 24 * time.Hour

// LoadOrCreateCA reads the authority from certFile and keyFile, generating a new
// one only when both are missing. An incomplete pair is an error: silently
// replacing the surviving half would invalidate a certificate somebody may
// already trust.
func LoadOrCreateCA(certFile, keyFile string) (*CA, error) {
	certPEM, certErr := os.ReadFile(certFile)
	keyPEM, keyErr := os.ReadFile(keyFile)
	if certErr == nil && keyErr == nil {
		ca, err := parseCA(certPEM, keyPEM)
		if err != nil {
			return nil, err
		}
		if err := chmod(keyFile, 0o600); err != nil {
			return nil, fmt.Errorf("proxy: securing %s: %w", keyFile, err)
		}
		return ca, nil
	}
	if certErr != nil && !os.IsNotExist(certErr) {
		return nil, fmt.Errorf("proxy: reading %s: %w", certFile, certErr)
	}
	if keyErr != nil && !os.IsNotExist(keyErr) {
		return nil, fmt.Errorf("proxy: reading %s: %w", keyFile, keyErr)
	}
	if os.IsNotExist(certErr) != os.IsNotExist(keyErr) {
		return nil, fmt.Errorf("proxy: incomplete authority: certificate and key must either both exist or both be absent")
	}

	certPEM, keyPEM, err := newCAMaterial()
	if err != nil {
		return nil, err
	}
	for _, file := range []string{certFile, keyFile} {
		if dir := filepath.Dir(file); dir != "" {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return nil, fmt.Errorf("proxy: %w", err)
			}
		}
	}
	// The key is the whole authority. Anyone who reads it can impersonate every
	// site to anyone who trusts this CA.
	if err := atomicfile.Write(keyFile, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("proxy: writing %s: %w", keyFile, err)
	}
	if err := atomicfile.Write(certFile, certPEM, 0o644); err != nil {
		_ = os.Remove(keyFile)
		return nil, fmt.Errorf("proxy: writing %s: %w", certFile, err)
	}
	// Parsed back from the PEM rather than kept from the generator, so that
	// there is exactly one path that turns bytes into a CA. The alternative
	// carried a re-parse whose failure could only mean the standard library
	// disagreeing with itself, which is not a branch worth writing.
	return parseCA(certPEM, keyPEM)
}

// newCAMaterial generates an authority and returns it as PEM.
func newCAMaterial() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), randReader)
	if err != nil {
		return nil, nil, fmt.Errorf("proxy: generating a key: %w", err)
	}
	serial, err := rand.Int(randReader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("proxy: serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "tls-forge proxy CA", Organization: []string{"tls-forge"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(randReader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("proxy: creating the authority: %w", err)
	}
	// Returned together: on failure the error is what the caller reads, and
	// there is no branch here that a P-256 key can ever take.
	keyPEM, err = encodeECKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPEM, err
}

// encodeECKey renders a private key as PEM.
//
// Separate because the failure is real for some curves and impossible for the
// one used here: x509 refuses to marshal a key on a curve it does not have an
// OID for. Keeping it in its own function is what lets that branch be tested
// without pretending the caller can hit it.
func encodeECKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("proxy: encoding the key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

func parseCA(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certBlock == nil || keyBlock == nil {
		return nil, fmt.Errorf("proxy: the authority files are not PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("proxy: parsing the authority: %w", err)
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("proxy: parsing the authority key: %w", err)
	}
	public, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("proxy: the authority certificate does not contain an ECDSA key")
	}
	if !public.Equal(&key.PublicKey) {
		return nil, fmt.Errorf("proxy: the authority certificate and key do not match")
	}
	if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("proxy: the authority certificate is not permitted to sign certificates")
	}
	current := time.Now()
	if current.Before(cert.NotBefore) || !current.Before(cert.NotAfter) {
		return nil, fmt.Errorf("proxy: the authority certificate is not currently valid")
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return nil, fmt.Errorf("proxy: the authority certificate is not self-signed: %w", err)
	}
	return &CA{cert: cert, key: key, pem: append([]byte(nil), certPEM...), leaves: map[string]*tls.Certificate{}}, nil
}

// CertPEM is the authority certificate, which is what a client has to trust.
func (c *CA) CertPEM() []byte { return append([]byte(nil), c.pem...) }

// leafFor returns a certificate for a host, minting one the first time.
//
// Cached because a browser opens many connections to one host and signing is
// the slowest thing this proxy does.
func (c *CA) leafFor(host string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cert, ok := c.leaves[host]; ok {
		return cert, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), randReader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(randReader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(caLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(randReader, template, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{Certificate: [][]byte{der, c.cert.Raw}, PrivateKey: key}
	c.leaves[host] = cert
	return cert, nil
}
