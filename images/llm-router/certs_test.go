package main

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"reflect"
	"testing"
	"time"
)

// note: pkix.Name comparisons use String() — parsed certs normalize the
// raw RDN fields that a literal DeepEqual would trip on.

func parsePEMCert(t *testing.T, pemBytes []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("no CERTIFICATE PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func TestNewCA(t *testing.T) {
	now := time.Now()
	authority, err := newCA(now)
	if err != nil {
		t.Fatalf("newCA: %v", err)
	}
	cert := parsePEMCert(t, authority.pemBytes())

	if !cert.IsCA {
		t.Errorf("IsCA = false")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Errorf("KeyUsage missing CertSign: %v", cert.KeyUsage)
	}
	if !cert.BasicConstraintsValid || cert.MaxPathLen != 1 {
		t.Errorf("basic constraints: valid=%v maxPathLen=%d", cert.BasicConstraintsValid, cert.MaxPathLen)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("public key type %T, want *rsa.PublicKey", cert.PublicKey)
	}
	if pub.N.BitLen() != 2048 {
		t.Errorf("CA key size = %d bits, want 2048", pub.N.BitLen())
	}
	// ~10 years of validity (NotBefore is backdated one hour).
	if validity := cert.NotAfter.Sub(cert.NotBefore); validity < 9*366*24*time.Hour {
		t.Errorf("CA validity = %v, want ~10y", validity)
	}
	if want := (pkix.Name{CommonName: "llm-router", Organization: []string{"mcp-eval"}}).String(); cert.Subject.String() != want {
		t.Errorf("subject = %q, want %q", cert.Subject.String(), want)
	}
}

func TestLeafForSANsAndSignature(t *testing.T) {
	now := time.Now()
	authority, err := newCA(now)
	if err != nil {
		t.Fatalf("newCA: %v", err)
	}
	const host = "api.openai.com"
	leaf, err := authority.leafFor(host, now)
	if err != nil {
		t.Fatalf("leafFor: %v", err)
	}
	if len(leaf.Certificate) != 2 {
		t.Fatalf("chain has %d certs, want leaf+CA", len(leaf.Certificate))
	}
	cert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	wantSANs := []string{host, "wildcard." + host, "*." + host}
	if !reflect.DeepEqual(cert.DNSNames, wantSANs) {
		t.Errorf("SANs = %v, want %v", cert.DNSNames, wantSANs)
	}
	for _, name := range wantSANs {
		if err := cert.VerifyHostname(name); err != nil {
			t.Errorf("VerifyHostname(%q): %v", name, err)
		}
	}

	// The leaf must chain to the boot CA.
	pool := x509.NewCertPool()
	pool.AddCert(parsePEMCert(t, authority.pemBytes()))
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: now.Add(time.Hour),
		DNSName:     host,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("verify leaf against CA: %v", err)
	}
	if cert.NotAfter.After(authority.cert.NotAfter) {
		t.Errorf("leaf NotAfter %v outlives CA %v", cert.NotAfter, authority.cert.NotAfter)
	}

	// The private key in the tls.Certificate must match the certified public key.
	key, ok := leaf.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("leaf key type %T, want *rsa.PrivateKey", leaf.PrivateKey)
	}
	if key.PublicKey.N.Cmp(cert.PublicKey.(*rsa.PublicKey).N) != 0 {
		t.Errorf("leaf private key does not match certificate public key")
	}
}

func TestHostList(t *testing.T) {
	got := hostList("api.openai.com, api.anthropic.com,,API.OpenAI.com,openrouter.ai,10.0.0.1,")
	want := []string{"api.openai.com", "api.anthropic.com", "openrouter.ai"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("hostList = %v, want %v", got, want)
	}
	if got := hostList(defaultLLMHosts); len(got) != 8 {
		t.Errorf("default LLM_HOSTS parsed to %d hosts, want 8: %v", len(got), got)
	}
	if got := hostList("  ,,"); got != nil {
		t.Errorf("hostList of blanks = %v, want nil", got)
	}
}
