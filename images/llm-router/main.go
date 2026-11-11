// llm-router — transparent LLM-endpoint redirector.
//
// One container: apps inside it keep calling https://api.openai.com,
// https://api.anthropic.com, ... with their usual SDKs and model names, but
// the entrypoint maps those hosts to 127.0.0.1 in the container's own
// /etc/hosts, so the TLS connection lands on this router. The router answers
// with a boot-generated CA + per-host leaf (exported to the system trust
// store) and forwards everything to the platform gateway (Occludra), which
// fronts the local LLM. Traffic NOT targeting an LLM_HOSTS host is never
// intercepted: it resolves normally and leaves the container untouched.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

const (
	defaultLLMHosts = "api.openai.com,api.anthropic.com,openrouter.ai,api.groq.com,gateway.ai.cloudflare.com,api.cohere.com,api.mistral.ai,opencode.ai"
	defaultTarget   = "http://127.0.0.1:30080" // entrypoint port-forwards svc/occludra-service here
	defaultTLSAddr  = ":443"
	defaultHealthLn = ":8080"
	defaultCAPath   = "/usr/local/share/ca-certificates/llm-router.crt"
)

type config struct {
	hosts     []string
	target    *url.URL
	token     string
	tlsAddr   string
	healthLn  string
	caPath    string
	updateCAs bool
}

func configFromEnv() (config, error) {
	target, err := url.Parse(getenv("OCCLUDRA_URL", defaultTarget))
	if err != nil || target.Scheme == "" || target.Host == "" {
		return config{}, fmt.Errorf("invalid OCCLUDRA_URL %q", os.Getenv("OCCLUDRA_URL"))
	}
	hosts := hostList(getenv("LLM_HOSTS", defaultLLMHosts))
	if len(hosts) == 0 {
		return config{}, fmt.Errorf("LLM_HOSTS has no usable hostnames")
	}
	return config{
		hosts:     hosts,
		target:    target,
		token:     os.Getenv("OCCLUDRA_TOKEN"), // empty = passthrough auth
		tlsAddr:   getenv("TLS_LISTEN", defaultTLSAddr),
		healthLn:  getenv("HEALTH_LISTEN", defaultHealthLn),
		caPath:    getenv("CA_BUNDLE_PATH", defaultCAPath),
		updateCAs: os.Getenv("SKIP_UPDATE_CA_CERTS") != "1",
	}, nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	log.SetPrefix("llm-router: ")
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	cfg, err := configFromEnv()
	if err != nil {
		log.Fatalf("%v", err)
	}
	if err := run(cfg); err != nil {
		log.Fatalf("%v", err)
	}
}

func run(cfg config) error {
	log.Printf("intercepting %v -> %s (auth: %s)", cfg.hosts, cfg.target, authMode(cfg.token))

	// Boot PKI: in-memory CA, per-host leaves, CA exported for the apps.
	authority, err := newCA(time.Now())
	if err != nil {
		return err
	}
	tlsCfg, err := authority.buildTLSConfig(cfg.hosts, time.Now())
	if err != nil {
		return err
	}
	if err := writeCABundle(cfg.caPath, authority.pemBytes()); err != nil {
		return fmt.Errorf("write CA bundle: %w", err)
	}
	log.Printf("CA written to %s", cfg.caPath)
	if cfg.updateCAs {
		refreshSystemCAs() // best-effort; absent outside the container
	}

	read, idle := serverTimeouts()
	proxy := newGatewayProxy(cfg.target, cfg.token)

	tlsSrv := &http.Server{
		Addr:        cfg.tlsAddr,
		Handler:     proxy,
		TLSConfig:   tlsCfg,
		ReadTimeout: read, // headers + body of each request
		IdleTimeout: idle, // keep-alive between requests
		// no WriteTimeout: SSE answers may stream for a long time
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}, // HTTP/1.1 only — proxies stream it faithfully
	}
	healthSrv := &http.Server{
		Addr:         cfg.healthLn,
		Handler:      newHealthHandler(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  idle,
	}

	healthErr := make(chan error, 1)
	go func() { healthErr <- healthSrv.ListenAndServe() }()
	log.Printf("tls on %s (SNI per host), health on %s/healthz", cfg.tlsAddr, cfg.healthLn)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	serveErr := make(chan error, 1)
	go func() { serveErr <- tlsSrv.ListenAndServeTLS("", "") }() // certs from TLSConfig

	for {
		select {
		case err := <-serveErr:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return fmt.Errorf("tls server: %w", err)
		case err := <-healthErr:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return fmt.Errorf("health server: %w", err)
		case s := <-sig:
			log.Printf("signal %v, draining", s)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = tlsSrv.Shutdown(ctx)
			_ = healthSrv.Shutdown(ctx)
			cancel()
			return nil
		}
	}
}

func authMode(token string) string {
	if token == "" {
		return "passthrough (OCCLUDRA_TOKEN unset: client Authorization forwarded unchanged)"
	}
	return "gateway bearer token"
}

// writeCABundle stores the CA PEM where update-ca-certificates picks it up
// (creating parent directories as needed).
func writeCABundle(path string, pemBytes []byte) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, pemBytes, 0o644)
}

// refreshSystemCAs runs update-ca-certificates so every app in the container
// (curl, python, node with NODE_EXTRA_CA_CERTS pointing at the same file,
// ...) trusts the boot CA. Outside the container the binary is simply absent
// and the call is a no-op.
func refreshSystemCAs() {
	bin, err := exec.LookPath("update-ca-certificates")
	if err != nil {
		log.Printf("update-ca-certificates not found; skipping system CA refresh")
		return
	}
	out, err := exec.Command(bin).CombinedOutput()
	if err != nil {
		log.Printf("update-ca-certificates failed: %v: %s", err, out)
		return
	}
	log.Printf("system CA bundle updated (%s)", bin)
}
