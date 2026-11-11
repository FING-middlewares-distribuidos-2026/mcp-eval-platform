// The forwarding core: every request the router answers on :443 is sent to
// the platform gateway (Occludra) with the caller's Authorization replaced by
// the gateway bearer token and X-Occludra-Client: external stamped on it, so
// the traffic gets the designed per-client screening (Vigil both ways, PII /
// secret DLP, model policy). Method, path, query and body pass through
// untouched — including streaming (SSE) responses.
package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

const clientHeader = "X-Occludra-Client"

// newGatewayProxy returns a handler forwarding everything to target (the
// Occludra gateway). When token is non-empty the inbound Authorization is
// stripped and replaced with "Bearer <token>"; otherwise the caller's own
// Authorization is forwarded unchanged.
func newGatewayProxy(target *url.URL, token string) http.Handler {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target) // scheme + host of the gateway; path/query kept
			pr.Out.Host = target.Host
			pr.SetXForwarded() // X-Forwarded-For/Host: the gateway logs stay useful

			pr.Out.Header.Set(clientHeader, "external")
			if token != "" {
				pr.Out.Header.Del("Authorization")
				pr.Out.Header.Set("Authorization", "Bearer "+token)
			}
		},
		// Flush after every Write: SSE chunks must reach the client as the
		// gateway emits them, never buffered into a whole body.
		FlushInterval: -1,
		Transport: &http.Transport{
			Proxy: nil, // never loop through a corporate proxy on the way out
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
			// The model can take a while to start answering; the screening
			// verdict itself is sub-second. 240s mirrors the read timeout.
			ResponseHeaderTimeout: 240 * time.Second,
		},
		ErrorHandler: gatewayUnavailable,
	}
	return proxy
}

// gatewayUnavailable answers connection-level failures to the gateway with
// an OpenAI-shaped error so SDKs surface something recognizable.
func gatewayUnavailable(w http.ResponseWriter, _ *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadGateway)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"message": "llm-router: gateway unreachable",
			"type":    "llm_router_error",
			"code":    "gateway_unreachable",
			"detail":  err.Error(),
		},
	})
}

// newHealthHandler serves the docker health endpoint on plain HTTP (:8080).
func newHealthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

// serverTimeouts is shared by both listeners: a generous read window (large
// prompts and slow clients), no write deadline (hours-long SSE streams must
// not be cut mid-answer) and a long keep-alive idle timeout.
func serverTimeouts() (read, idle time.Duration) {
	return 240 * time.Second, 600 * time.Second
}
