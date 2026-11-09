package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// shippedPolicy loads the policy the cluster actually runs: the
// occludra-policy ConfigMap in manifests/occludra-deployment.yaml.
func shippedPolicy(t *testing.T) *Policy {
	t.Helper()
	raw, err := os.ReadFile("../../manifests/occludra-deployment.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	for {
		var doc struct {
			Kind     string                `yaml:"kind"`
			Metadata struct{ Name string } `yaml:"metadata"`
			Data     map[string]string     `yaml:"data"`
		}
		if err := dec.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatal(err)
		}
		if doc.Kind == "ConfigMap" && doc.Metadata.Name == "occludra-policy" {
			path := filepath.Join(t.TempDir(), "policy.yaml")
			if err := os.WriteFile(path, []byte(doc.Data["policy.yaml"]), 0o600); err != nil {
				t.Fatal(err)
			}
			p, err := loadPolicy(path)
			if err != nil {
				t.Fatal(err)
			}
			return p
		}
	}
	t.Fatal("occludra-policy ConfigMap not found")
	return nil
}

// No piece of a credential may survive redaction: an earlier, broader
// detector must not mask part of it and leave the rest unmatched.
func TestShippedPolicyRedactsWholeCredentials(t *testing.T) {
	p := shippedPolicy(t)
	secrets := map[string]string{
		"github token with digits": "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB",
		"openai key with digits":   "sk-proj-1234567890abcdefGHIJKLmnop",
		"aws access key":           "AKIA1234567890ABCDEF",
		"bearer header":            "Authorization: Bearer 1234567890abcdefghijklmnop",
		"password sentence":        "password: 12345678abcd",
		"spanish clave":            "clave=Sup3rS3creta!2026",
		"spanish contraseña":       "mi contraseña es Hunter2Hunter2xy",
		"contraseña with words":    "la contraseña del servidor es Zq9!pLm2vX4w",
		"spanish token":            "el token de acceso es 9f8e7d6c5b4a3f2e1d0c",
	}
	for name, secret := range secrets {
		stats := &requestStats{redactions: map[string]int{}}
		out := redactString("mi dato es "+secret+" gracias", p, stats)
		// Every 6-character window of the secret's tail must be gone.
		tail := secret[len(secret)-12:]
		for i := 0; i+6 <= len(tail); i++ {
			if strings.Contains(out, tail[i:i+6]) {
				t.Errorf("%s: %q survived in %q", name, tail[i:i+6], out)
				break
			}
		}
	}
}

// Ordinary Spanish prose that mentions the keywords must not be masked.
func TestShippedPolicyLeavesPlainSpanishAlone(t *testing.T) {
	p := shippedPolicy(t)
	for _, text := range []string{
		"La clave del problema es entender el scheduler de Kubernetes.",
		"Olvidé mi contraseña, ¿cómo la recupero?",
		"Los tokens se cuentan distinto en OpenCode.",
	} {
		stats := &requestStats{redactions: map[string]int{}}
		if out := redactString(text, p, stats); out != text {
			t.Errorf("plain text was rewritten: %q -> %q", text, out)
		}
	}
}
