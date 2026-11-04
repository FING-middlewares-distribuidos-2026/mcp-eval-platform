// Two-sided Vigil prompt-injection scanning (VIGIL_SCAN_IN / VIGIL_SCAN_OUT).
//
// Vigil (vigil-llm) is the platform's prompt-injection scanner, deployed in
// this same namespace (vigil-service:5000). The evaluator already scans
// untrusted payloads inbound before formatting them into prompts; these knobs
// give the gateway itself the same eyes, so traffic that only traverses
// Occludra (the workstation / OpenCode path) is scanned on the way in AND on
// the way out.
//
// Contract (all fail-soft; disabled means byte-identical passthrough):
//
//	VIGIL_SCAN_IN=1     before proxying a completion request, concatenate the
//	                    message text (capped, see maxVigilScanBytes) and POST
//	                    {"prompt": text} to VIGIL_URL. VIGIL_IN_ACTION=block
//	                    answers 403 vigil_block instead of proxying; default
//	                    "log" proxies anyway (log + metric only).
//	VIGIL_SCAN_OUT=1    after a response completes, POST {"response": text} to
//	                    VIGIL_RESPONSE_URL (derived from VIGIL_URL by swapping
//	                    the trailing /analyze/prompt for /analyze/response).
//	                    Log + metric only — the response stream is never
//	                    mutated or blocked.
//	VIGIL_TIMEOUT_MS    per-scan timeout (default 3000). Timeout, unreachable
//	                    or 5xx Vigil → one classified log line, metric
//	                    verdict="error", request passes through.
//
// Verdict parsing mirrors the leniency of runner/src/vigil.ts across the
// shapes actual vigil-llm releases emit; an unrecognized shape is treated as
// a scanner error — never silently as "clean". Log lines carry
// direction/verdict/class only: never prompt or response content.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

// maxVigilScanBytes caps the text sent to Vigil per scan (the scanners score
// the head of the payload; longer requests are truncated with a marker).
const maxVigilScanBytes = 16384

const vigilTruncationMarker = "\n…[truncated by occludra for vigil scan]"

const vigilPromptPathSuffix = "/analyze/prompt"

const vigilResponsePathSuffix = "/analyze/response"

// vigilConfig is resolved once at boot; a nil *vigilConfig means scanning is
// fully disabled and the gateway skips every scan path.
type vigilConfig struct {
	scanIn      bool
	scanOut     bool
	inAction    string // "log" (default) | "block"
	promptURL   string
	responseURL string
	client      *http.Client
}

// newVigilConfigFromEnv resolves the VIGIL_* knobs. It returns nil unless at
// least one direction is enabled. When VIGIL_SCAN_OUT is requested but the
// response endpoint cannot be derived (VIGIL_URL does not end in
// /analyze/prompt and no VIGIL_RESPONSE_URL is set), out-scanning is disabled
// with a single warning at boot rather than guessing a URL.
func newVigilConfigFromEnv() *vigilConfig {
	cfg := &vigilConfig{
		scanIn:    envEnabled("VIGIL_SCAN_IN"),
		scanOut:   envEnabled("VIGIL_SCAN_OUT"),
		inAction:  envOr("VIGIL_IN_ACTION", "log"),
		promptURL: strings.TrimSpace(os.Getenv("VIGIL_URL")),
		client: &http.Client{
			Timeout: time.Duration(envInt("VIGIL_TIMEOUT_MS", 3000)) * time.Millisecond,
		},
	}
	if !cfg.scanIn && !cfg.scanOut {
		return nil
	}
	if cfg.promptURL == "" {
		cfg.promptURL = "http://vigil-service.security-gateways.svc.cluster.local:5000" + vigilPromptPathSuffix
	}
	if raw := strings.TrimSpace(os.Getenv("VIGIL_RESPONSE_URL")); raw != "" {
		cfg.responseURL = raw
	} else if base, ok := strings.CutSuffix(cfg.promptURL, vigilPromptPathSuffix); ok {
		cfg.responseURL = base + vigilResponsePathSuffix
	} else if cfg.scanOut {
		log.Printf("vigil direction=out disabled: VIGIL_URL does not end in %s and VIGIL_RESPONSE_URL is unset", vigilPromptPathSuffix)
		cfg.scanOut = false
	}
	if cfg.inAction != "block" {
		cfg.inAction = "log"
	}
	return cfg
}

// envEnabled interprets the platform's truthy env values ("1" etc.); anything
// else — including unset — keeps the knob off.
func envEnabled(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// vigilScan POSTs text to the endpoint for direction ("in" → {"prompt": …},
// "out" → {"response": …}), classifies the outcome, bumps
// occludra_vigil_scans_total{direction, verdict} and logs one content-free
// line. It reports whether an injection was detected; every failure mode is
// fail-soft (verdict="error", returns false, caller passes through).
func (g *gateway) vigilScan(direction, text string) bool {
	cfg := g.vigil
	if cfg == nil {
		return false
	}
	endpoint, field := cfg.promptURL, "prompt"
	if direction == "out" {
		endpoint, field = cfg.responseURL, "response"
	}
	if endpoint == "" || strings.TrimSpace(text) == "" {
		vigilScans.WithLabelValues(direction, "skipped").Inc()
		return false
	}
	payload, err := json.Marshal(map[string]string{field: truncateForVigil(text)})
	if err != nil {
		vigilScans.WithLabelValues(direction, "error").Inc()
		log.Printf("vigil direction=%s verdict=encode_error", direction)
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		vigilScans.WithLabelValues(direction, "error").Inc()
		log.Printf("vigil direction=%s verdict=request_error", direction)
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := cfg.client.Do(req)
	if err != nil {
		vigilScans.WithLabelValues(direction, "error").Inc()
		log.Printf("vigil direction=%s verdict=%s", direction, vigilErrClass(err))
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		vigilScans.WithLabelValues(direction, "error").Inc()
		class := "server_error"
		if resp.StatusCode < 500 {
			class = "bad_status"
		}
		log.Printf("vigil direction=%s verdict=%s status=%d", direction, class, resp.StatusCode)
		return false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		vigilScans.WithLabelValues(direction, "error").Inc()
		log.Printf("vigil direction=%s verdict=read_error", direction)
		return false
	}
	detected, matched := interpretVigilVerdict(body)
	if !matched {
		vigilScans.WithLabelValues(direction, "error").Inc()
		log.Printf("vigil direction=%s verdict=unrecognized", direction)
		return false
	}
	verdict := "clean"
	if detected {
		verdict = "detect"
	}
	vigilScans.WithLabelValues(direction, verdict).Inc()
	log.Printf("vigil direction=%s verdict=%s", direction, verdict)
	return detected
}

// vigilErrClass maps a transport failure to a short, content-free class for
// the classified log line.
func vigilErrClass(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	return "unreachable"
}

// interpretVigilVerdict mirrors the lenient verdict parsing of
// runner/src/vigil.ts across the shapes actual vigil-llm releases emit.
// matched=false means no known shape applied — the caller treats that as a
// scanner error, never as "clean".
func interpretVigilVerdict(body []byte) (detected, matched bool) {
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil || parsed == nil {
		return false, false
	}
	// 1) Integration contract field.
	if v, ok := parsed["injection_detected"].(bool); ok {
		return v, true
	}
	// 2) Per-scanner matches (upstream ResponseModel: status stays "success"
	// on detections, so this must be checked BEFORE the status shape).
	if results, ok := parsed["results"].(map[string]any); ok {
		for name, r := range results {
			if name == "scanner:sentiment" {
				continue
			}
			if rm, ok := r.(map[string]any); ok {
				if matches, ok := rm["matches"].([]any); ok && len(matches) > 0 {
					return true, true
				}
			}
		}
		return false, true
	}
	// 3) Status-based shape.
	if status, ok := parsed["status"].(string); ok {
		switch strings.ToLower(status) {
		case "blocked", "malicious", "detected":
			return true, true
		}
		return false, true
	}
	// 4) Decision-based shape.
	switch decision := parsed["decision"].(type) {
	case map[string]any:
		if block, ok := decision["block"].(bool); ok {
			return block, true
		}
	case string:
		switch strings.ToLower(decision) {
		case "block", "blocked", "malicious", "injection":
			return true, true
		}
		return false, true
	}
	// 5) Verdict-string shape.
	if verdict, ok := parsed["verdict"].(string); ok {
		v := strings.ToLower(verdict)
		return strings.Contains(v, "inject") || strings.Contains(v, "jailbreak") || strings.Contains(v, "malicious"), true
	}
	return false, false
}

// truncateForVigil caps text at maxVigilScanBytes, cutting on a rune boundary
// and appending a visible marker.
func truncateForVigil(text string) string {
	if len(text) <= maxVigilScanBytes {
		return text
	}
	cut := maxVigilScanBytes
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut] + vigilTruncationMarker
}

// extractRequestText concatenates the model-facing text of a completion
// request body for inbound scanning. The same walk covers both inference wire
// formats the gateway routes here: /chat/completions messages[].content
// (string or content parts with a "text" field) and the Responses API input
// (string or message items with the same content shapes). Other fields
// (model, tools, options) are ignored.
func extractRequestText(obj map[string]any) string {
	var sb strings.Builder
	add := func(s string) {
		if s == "" {
			return
		}
		if sb.Len() > 0 {
			sb.WriteByte('\n')
		}
		sb.WriteString(s)
	}
	collectContent := func(content any) {
		switch typed := content.(type) {
		case string:
			add(typed)
		case []any:
			for _, part := range typed {
				if pm, ok := part.(map[string]any); ok {
					if text, ok := pm["text"].(string); ok {
						add(text)
					}
				}
			}
		}
	}
	if messages, ok := obj["messages"].([]any); ok {
		for _, item := range messages {
			if msg, ok := item.(map[string]any); ok {
				collectContent(msg["content"])
			}
		}
	}
	if input, ok := obj["input"]; ok {
		switch typed := input.(type) {
		case string:
			add(typed)
		case []any:
			for _, item := range typed {
				if msg, ok := item.(map[string]any); ok {
					collectContent(msg["content"])
				}
			}
		}
	}
	return sb.String()
}

// assistantTextFromJSON extracts the assistant text of a non-streaming
// inference response — the same shapes appendMarkerToJSON rewrites:
// chat.completions choices[].message.content (string or content parts) and
// the Responses API output[].content[].output_text.text. Unknown shapes yield
// "" (the scan is then recorded as skipped).
func assistantTextFromJSON(body []byte) string {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	var sb strings.Builder
	add := func(s string) {
		if s == "" {
			return
		}
		if sb.Len() > 0 {
			sb.WriteByte('\n')
		}
		sb.WriteString(s)
	}
	if choices, ok := payload["choices"].([]any); ok {
		for _, item := range choices {
			choice, ok := item.(map[string]any)
			if !ok {
				continue
			}
			msg, ok := choice["message"].(map[string]any)
			if !ok {
				continue
			}
			switch content := msg["content"].(type) {
			case string:
				add(content)
			case []any:
				for _, part := range content {
					if pm, ok := part.(map[string]any); ok {
						if text, ok := pm["text"].(string); ok {
							add(text)
						}
					}
				}
			}
		}
	}
	if outputs, ok := payload["output"].([]any); ok {
		for _, item := range outputs {
			output, ok := item.(map[string]any)
			if !ok {
				continue
			}
			contents, ok := output["content"].([]any)
			if !ok {
				continue
			}
			for _, part := range contents {
				pm, ok := part.(map[string]any)
				if !ok || pm["type"] != "output_text" {
					continue
				}
				if text, ok := pm["text"].(string); ok {
					add(text)
				}
			}
		}
	}
	return sb.String()
}

// sseTextCollector passively accumulates assistant text deltas from an SSE
// inference stream (chat.completions chunks and Responses API
// response.output_text.delta events) so the completed text can be out-scanned
// exactly once when the stream ends. It observes lines; it never modifies
// them or holds any back.
type sseTextCollector struct {
	sb strings.Builder
}

// line receives one SSE line (trailing newline already stripped, as produced
// by bufio.Scanner).
func (c *sseTextCollector) line(line string) {
	data, ok := strings.CutPrefix(strings.TrimSpace(line), "data:")
	if !ok {
		return
	}
	if c.sb.Len() >= maxVigilScanBytes {
		// The scan truncates at the cap anyway; stop accumulating so a
		// minutes-long stream cannot grow this buffer unbounded.
		return
	}
	var ev struct {
		Type    string          `json:"type"`
		Delta   json.RawMessage `json:"delta"`
		Choices []struct {
			Delta struct {
				Content any `json:"content"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(data)), &ev) != nil {
		return
	}
	if len(ev.Choices) > 0 {
		if s, ok := ev.Choices[0].Delta.Content.(string); ok {
			c.sb.WriteString(s)
		}
		return
	}
	if ev.Type == "response.output_text.delta" {
		var s string
		if json.Unmarshal(ev.Delta, &s) == nil {
			c.sb.WriteString(s)
		}
	}
}

func (c *sseTextCollector) text() string { return c.sb.String() }
