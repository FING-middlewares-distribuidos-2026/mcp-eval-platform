package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// routerEnv is a live router: a TLS listener on a local port serving
// per-host certs, proxying to an upstream.
type routerEnv struct {
	addr string // 127.0.0.1:<port> of the TLS listener
	pool *x509.CertPool
}

// startRouter boots the router's TLS side for hosts, forwarding to target
// with the given gateway token ("" = auth passthrough).
func startRouter(t *testing.T, hosts []string, target *url.URL, token string) *routerEnv {
	t.Helper()
	authority, err := newCA(time.Now())
	if err != nil {
		t.Fatalf("newCA: %v", err)
	}
	tlsCfg, err := authority.buildTLSConfig(hosts, time.Now())
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	read, idle := serverTimeouts()
	srv := &http.Server{
		Handler:     newGatewayProxy(target, token),
		TLSConfig:   tlsCfg,
		ReadTimeout: read,
		IdleTimeout: idle,
		// no WriteTimeout on purpose: streaming answers may take long
	}
	go func() { _ = srv.Serve(tls.NewListener(ln, tlsCfg)) }()
	t.Cleanup(func() { _ = srv.Close() })

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(authority.pemBytes())
	return &routerEnv{addr: ln.Addr().String(), pool: pool}
}

const (
	testToken   = "sekrit-gateway-token"
	clientToken = "sk-client-original-credentials"
)

// clientFor returns a client that connects to the router's real address
// while presenting the TLS identity (SNI + Host) of serverName, exactly like
// an SDK inside the container would after /etc/hosts maps it to 127.0.0.1.
func clientFor(t *testing.T, addr string, pool *x509.CertPool, serverName string) *http.Client {
	t.Helper()
	return &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2: false,
			DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				dialer := net.Dialer{}
				conn, err := dialer.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				return tls.Client(conn, &tls.Config{
					ServerName: serverName,
					RootCAs:    pool,
					NextProtos: []string{"http/1.1"},
				}), nil
			},
		},
	}
}

// capturedRequest is what the fake gateway saw.
type capturedRequest struct {
	method      string
	path        string // path + raw query
	host        string
	auth        string
	clientHdr   string
	contentType string
	body        string
}

// startUpstream records the last request and answers with wantStatus/wantBody.
func startUpstream(t *testing.T, status int, body string) (*httptest.Server, *capturedRequest) {
	t.Helper()
	got := &capturedRequest{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		got.method = r.Method
		got.path = r.URL.Path + "?" + r.URL.RawQuery
		got.host = r.Host
		got.auth = r.Header.Get("Authorization")
		got.clientHdr = r.Header.Get("X-Occludra-Client")
		got.contentType = r.Header.Get("Content-Type")
		got.body = string(bodyBytes)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(upstream.Close)
	return upstream, got
}

func TestProxyRewritesAuthAndPreservesRequest(t *testing.T) {
	upstream, got := startUpstream(t, 200, `{"role":"assistant","model":"gemma-4-12b-it"}`)
	target, _ := url.Parse(upstream.URL)
	env := startRouter(t, []string{"api.openai.com"}, target, testToken)

	client := clientFor(t, env.addr, env.pool, "api.openai.com")
	reqBody := `{"model":"gpt-4o","messages":[{"role":"user","content":"hola"}]}`
	req, err := http.NewRequest(http.MethodPost,
		"https://api.openai.com/v1/chat/completions?stream=false",
		strings.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+clientToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request through router: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if string(respBody) != `{"role":"assistant","model":"gemma-4-12b-it"}` {
		t.Errorf("response body = %q", respBody)
	}
	// The gateway sees OUR credentials, never the client's.
	if got.auth != "Bearer "+testToken {
		t.Errorf("upstream Authorization = %q, want gateway bearer", got.auth)
	}
	if strings.Contains(got.auth, clientToken) {
		t.Errorf("client credentials leaked to gateway: %q", got.auth)
	}
	if got.clientHdr != "external" {
		t.Errorf("upstream X-Occludra-Client = %q, want external", got.clientHdr)
	}
	// Method, path, query, body and content type pass through untouched.
	if got.method != http.MethodPost {
		t.Errorf("upstream method = %s", got.method)
	}
	if got.path != "/v1/chat/completions?stream=false" {
		t.Errorf("upstream path+query = %q", got.path)
	}
	if got.body != reqBody {
		t.Errorf("upstream body = %q, want %q", got.body, reqBody)
	}
	if got.contentType != "application/json" {
		t.Errorf("upstream Content-Type = %q", got.contentType)
	}
	// Host points at the gateway, not at the faked LLM vendor.
	if got.host != target.Host {
		t.Errorf("upstream Host = %q, want %q", got.host, target.Host)
	}
}

func TestProxyPassthroughAuthWhenNoToken(t *testing.T) {
	upstream, got := startUpstream(t, 200, "{}")
	target, _ := url.Parse(upstream.URL)
	env := startRouter(t, []string{"api.anthropic.com"}, target, "") // no gateway token

	client := clientFor(t, env.addr, env.pool, "api.anthropic.com")
	req, _ := http.NewRequest(http.MethodGet, "https://api.anthropic.com/v1/messages", nil)
	req.Header.Set("Authorization", "Bearer "+clientToken)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got.auth != "Bearer "+clientToken {
		t.Errorf("Authorization = %q, want the client's own token forwarded unchanged", got.auth)
	}
	if got.clientHdr != "external" {
		t.Errorf("X-Occludra-Client = %q, want external", got.clientHdr)
	}
}

func TestSNIServesPerHostCert(t *testing.T) {
	upstream, _ := startUpstream(t, 200, "{}")
	target, _ := url.Parse(upstream.URL)
	env := startRouter(t, []string{"api.openai.com", "api.anthropic.com", "openrouter.ai"}, target, testToken)

	serials := map[string]bool{}
	for _, host := range []string{"api.openai.com", "api.anthropic.com", "openrouter.ai"} {
		client := clientFor(t, env.addr, env.pool, host)
		resp, err := client.Get("https://" + host + "/v1/models")
		if err != nil {
			t.Fatalf("GET via %s: %v", host, err)
		}
		resp.Body.Close()

		// Re-dial manually to inspect the peer certificate.
		conn, err := tls.Dial("tcp", env.addr, &tls.Config{
			ServerName: host,
			RootCAs:    env.pool,
			NextProtos: []string{"http/1.1"},
		})
		if err != nil {
			t.Fatalf("tls dial for %s: %v", host, err)
		}
		peer := conn.ConnectionState().PeerCertificates[0]
		if err := peer.VerifyHostname(host); err != nil {
			t.Errorf("SNI %s got a cert that does not cover it: %v", host, err)
		}
		serial := peer.SerialNumber.String()
		if serials[serial] {
			t.Errorf("SNI %s reused another host's certificate", host)
		}
		serials[serial] = true
		_ = conn.Close()
	}
}

// TestSSEStreamPassthrough proves chunk-by-chunk flushing: the upstream
// refuses to emit the second chunk until the client has read the first —
// if the router buffered, this would deadlock into the timeout.
func TestSSEStreamPassthrough(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		flusher := w.(http.Flusher)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: first\n\n"))
		flusher.Flush()
		<-release // hold the second chunk until the client saw the first
		_, _ = w.Write([]byte("data: second\n\n"))
		flusher.Flush()
	}))
	t.Cleanup(upstream.Close)
	target, _ := url.Parse(upstream.URL)
	env := startRouter(t, []string{"api.openai.com"}, target, testToken)

	type result struct {
		events []string
		err    error
	}
	done := make(chan result, 1)
	go func() {
		client := clientFor(t, env.addr, env.pool, "api.openai.com")
		resp, err := client.Post("https://api.openai.com/v1/chat/completions", "application/json",
			strings.NewReader(`{"model":"gpt-4o","stream":true}`))
		if err != nil {
			done <- result{err: err}
			return
		}
		defer resp.Body.Close()
		var events []string
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") {
				events = append(events, strings.TrimPrefix(line, "data: "))
				if len(events) == 1 {
					close(release) // first chunk reached the client: let the second flow
				}
			}
		}
		done <- result{events: events, err: scanner.Err()}
	}()

	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("stream read: %v", res.err)
		}
		if len(res.events) != 2 || res.events[0] != "first" || res.events[1] != "second" {
			t.Fatalf("events = %v, want [first second] in flushed order", res.events)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("stream stalled: first chunk never reached the client before the second was written (buffering)")
	}
}

func TestGatewayDownReturns502(t *testing.T) {
	// Reserve a port, then close it so nothing answers there.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().String()
	_ = dead.Close()
	target, _ := url.Parse("http://" + deadAddr)
	env := startRouter(t, []string{"api.openai.com"}, target, testToken)

	client := clientFor(t, env.addr, env.pool, "api.openai.com")
	resp, err := client.Get("https://api.openai.com/v1/chat/completions")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	var parsed struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Code    string `json:"code"`
			Detail  string `json:"detail"`
		} `json:"error"`
	}
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&parsed); err != nil {
		t.Fatalf("decode 502 body %q: %v", body, err)
	}
	if parsed.Error.Message != "llm-router: gateway unreachable" {
		t.Errorf("error.message = %q", parsed.Error.Message)
	}
	if parsed.Error.Type != "llm_router_error" || parsed.Error.Code != "gateway_unreachable" {
		t.Errorf("error.type/code = %q/%q", parsed.Error.Type, parsed.Error.Code)
	}
	if parsed.Error.Detail == "" {
		t.Errorf("error.detail empty: connection error not reported")
	}
}

func TestHealthz(t *testing.T) {
	server := httptest.NewServer(newHealthHandler())
	t.Cleanup(server.Close)
	resp, err := server.Client().Get(server.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != "ok" {
		t.Errorf("body = %q, want ok", body)
	}
}
