// In-memory PKI for the transparent router: one CA generated at boot, one
// leaf certificate per intercepted LLM host. The CA PEM is exported to the
// system trust store (see main.go) so apps inside the container accept the
// leaf certs without any code change on their side.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

const (
	rsaKeyBits = 2048
	// CA validity: 10 years — regenerated every boot, so it only has to
	// outlive the container.
	caValidity = 10 * 365 * 24 * time.Hour
	// Leaves: CA validity minus a safety margin.
	leafValidity = caValidity - 24*time.Hour
)

// ca is the boot-generated certificate authority.
type ca struct {
	cert    *x509.Certificate
	key     crypto.Signer
	certPEM []byte
}

// newCA generates a self-signed RSA-2048 CA valid for ~10 years.
func newCA(now time.Time) (*ca, error) {
	key, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "llm-router", Organization: []string{"mcp-eval"}},
		NotBefore:             now.Add(-time.Hour), // tolerate clock skew
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1, // signs leaves only
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("create CA cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}
	return &ca{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}, nil
}

// pemBytes returns the CA certificate in PEM form, ready for the trust store.
func (c *ca) pemBytes() []byte { return c.certPEM }

// leafFor signs a server certificate for host with SANs
// [host, wildcard.<host>, *.<host>] — the exact host for the apps, the
// wildcard spellings for anything that connects to a subdomain.
func (c *ca) leafFor(host string, now time.Time) (*tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key for %s: %w", host, err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{"mcp-eval"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(leafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host, "wildcard." + host, "*." + host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, key.Public(), c.key)
	if err != nil {
		return nil, fmt.Errorf("create leaf cert for %s: %w", host, err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, c.cert.Raw}, // leaf + chain
		PrivateKey:  key,
	}, nil
}

// buildTLSConfig returns a server-side TLS config that answers each SNI name
// in hosts with its own leaf. Unknown or missing SNI falls back to the first
// host's leaf — interception is decided by /etc/hosts, not by SNI.
func (c *ca) buildTLSConfig(hosts []string, now time.Time) (*tls.Config, error) {
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no hosts to serve")
	}
	leaves := make(map[string]*tls.Certificate, len(hosts))
	var fallback *tls.Certificate
	for _, h := range hosts {
		leaf, err := c.leafFor(h, now)
		if err != nil {
			return nil, err
		}
		leaves[h] = leaf
		if fallback == nil {
			fallback = leaf
		}
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := strings.TrimSuffix(strings.ToLower(hello.ServerName), ".")
			if leaf, ok := leaves[name]; ok {
				return leaf, nil
			}
			return fallback, nil
		},
	}, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 127) // positive, up to 128 bits
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return n, nil
}

// hostList splits a comma-separated LLM_HOSTS value, lower-casing (DNS names
// and SNI are case-insensitive), trimming blanks and dropping duplicates.
func hostList(raw string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, part := range strings.Split(raw, ",") {
		h := strings.ToLower(strings.TrimSpace(part))
		if h == "" || seen[h] {
			continue
		}
		if net.ParseIP(h) != nil {
			continue // hosts, not IPs
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}
