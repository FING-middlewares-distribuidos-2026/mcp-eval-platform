package main

// Prompt-injection screening in both directions, for named clients only.
//
// Outbound ("ida"): before a request goes upstream, the text of the turn the
// client is sending (user and tool messages after the last assistant answer,
// already redacted) is scanned by Vigil. Inbound ("vuelta"): the model's
// answer is buffered, its text scanned, and only then released.
//
// Only clients listed in policy.injection.clients are screened (the UI chat,
// external OpenCode clients). Evaluation traffic names no client and is never
// screened here: the evaluator scans MCP output with Vigil itself, and its
// prompts quote the hostile MCP under test on purpose.
//
//	OCCLUDRA_VIGIL_URL         Vigil base URL, e.g. http://vigil-service:5000
//	                           (screening is off when unset)
//	OCCLUDRA_VIGIL_TIMEOUT_MS  per-scan timeout (default 60000)

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type InjectionPolicy struct {
	// Clients (X-Occludra-Client) whose traffic is screened.
	Clients       []string `yaml:"clients"`
	ScanRequests  bool     `yaml:"scan_requests"`
	ScanResponses bool     `yaml:"scan_responses"`
	// OnVigilError: "block" (default) refuses the request when Vigil cannot
	// answer; "allow" lets it through unscreened.
	OnVigilError string `yaml:"on_vigil_error"`
	// MinScanners is how many different Vigil scanners must flag a text to
	// refuse it (default 1: any scanner). Fewer is a warning: logged and
	// counted, the traffic passes.
	MinScanners int `yaml:"min_scanners"`
	// CountScanners limits which scanners count toward MinScanners, by
	// case-insensitive prefix of the name Vigil reports ("YARA" matches
	// "YARA signature(s)"). Empty: every scanner counts. The others are
	// still reported, as warnings.
	CountScanners []string `yaml:"count_scanners"`
}

// counted returns the scanners that count toward MinScanners.
func (p InjectionPolicy) counted(scanners []string) []string {
	if len(p.CountScanners) == 0 {
		return scanners
	}
	var out []string
	for _, s := range scanners {
		for _, want := range p.CountScanners {
			if w := strings.TrimSpace(want); w != "" && len(s) >= len(w) && strings.EqualFold(s[:len(w)], w) {
				out = append(out, s)
				break
			}
		}
	}
	return out
}

func (p InjectionPolicy) minScanners() int {
	if p.MinScanners < 1 {
		return 1
	}
	return p.MinScanners
}

func (p InjectionPolicy) screens(client string) bool {
	if client == "" {
		return false
	}
	for _, c := range p.Clients {
		if c == client {
			return true
		}
	}
	return false
}

func (p InjectionPolicy) failOpen() bool {
	return strings.EqualFold(strings.TrimSpace(p.OnVigilError), "allow")
}

// injectionVerdict is what the journal and the client learn about a scan.
type injectionVerdict struct {
	Direction string   `json:"direction"` // "request" | "response"
	Scanners  []string `json:"scanners,omitempty"`
	Error     string   `json:"error,omitempty"`
}

type vigilClient struct {
	url     string
	client  *http.Client
	timeout time.Duration
}

func newVigilClient() *vigilClient {
	base := strings.TrimRight(strings.TrimSpace(os.Getenv("OCCLUDRA_VIGIL_URL")), "/")
	if base == "" {
		return nil
	}
	if !strings.HasSuffix(base, "/analyze/prompt") {
		base += "/analyze/prompt"
	}
	timeout := time.Duration(envInt("OCCLUDRA_VIGIL_TIMEOUT_MS", 60000)) * time.Millisecond
	return &vigilClient{url: base, client: &http.Client{Timeout: timeout}, timeout: timeout}
}

const vigilHit = "Potential prompt injection detected: "

// scan returns the scanners that flagged text (empty: clean). Vigil lists a
// "Potential prompt injection detected: <scanner>" message for every scanner
// whose match counts, the same signal the evaluator acts on.
func (v *vigilClient) scan(ctx context.Context, text string) ([]string, error) {
	body, _ := json.Marshal(map[string]string{"prompt": text})
	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vigil answered HTTP %d", resp.StatusCode)
	}
	var verdict struct {
		Messages []string `json:"messages"`
	}
	if err := json.Unmarshal(raw, &verdict); err != nil {
		return nil, errors.New("vigil answer is not JSON")
	}
	var scanners []string
	seen := map[string]bool{}
	for _, m := range verdict.Messages {
		if rest, ok := strings.CutPrefix(m, vigilHit); ok {
			if name := strings.TrimSpace(rest); !seen[name] {
				seen[name] = true
				scanners = append(scanners, name)
			}
		}
	}
	return scanners, nil
}

// outboundText is the text of the turn being sent: user and tool content
// after the last assistant message. System prompts are the client's own and
// would only add false positives; earlier turns were screened when sent.
func outboundText(obj map[string]any) string {
	var parts []string
	if msgs, ok := obj["messages"].([]any); ok { // chat/completions
		parts = trailingTurn(msgs, func(m map[string]any) string {
			role, _ := m["role"].(string)
			return role
		})
	} else if input, ok := obj["input"].([]any); ok { // /responses
		parts = trailingTurn(input, func(m map[string]any) string {
			if role, ok := m["role"].(string); ok {
				return role
			}
			if t, _ := m["type"].(string); t == "function_call_output" {
				return "tool"
			}
			return "assistant" // function_call and other model-side items
		})
	} else if s, ok := obj["input"].(string); ok {
		parts = []string{s}
	}
	return strings.TrimSpace(strings.Join(parts, "\n"))
}

func trailingTurn(items []any, role func(map[string]any) string) []string {
	start := 0
	for i, item := range items {
		if m, ok := item.(map[string]any); ok && role(m) == "assistant" {
			start = i + 1
		}
	}
	var parts []string
	for _, item := range items[start:] {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if r := role(m); r != "user" && r != "tool" {
			continue
		}
		for _, key := range []string{"content", "output"} {
			parts = append(parts, collectText(m[key])...)
		}
	}
	return parts
}

// collectText gathers the human-readable strings of a message content value:
// a plain string, or parts like {"type":"text","text":...}.
func collectText(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, item := range t {
			out = append(out, collectText(item)...)
		}
		return out
	case map[string]any:
		if s, ok := t["text"].(string); ok {
			return []string{s}
		}
		if s, ok := t["content"].(string); ok {
			return []string{s}
		}
	}
	return nil
}

// answerText extracts the model's text from a buffered answer: an SSE stream
// (chat deltas or Responses output_text deltas) or a plain JSON body.
func answerText(body []byte, sse bool) string {
	var b strings.Builder
	if sse {
		scanner := bufio.NewScanner(bytes.NewReader(body))
		scanner.Buffer(make([]byte, 0, 64*1024), maxBodyBytes)
		for scanner.Scan() {
			line, ok := strings.CutPrefix(scanner.Text(), "data:")
			if !ok {
				continue
			}
			var ev map[string]any
			if json.Unmarshal([]byte(strings.TrimSpace(line)), &ev) != nil {
				continue
			}
			if t, _ := ev["type"].(string); t == "response.output_text.delta" {
				if d, ok := ev["delta"].(string); ok {
					b.WriteString(d)
				}
				continue
			}
			for _, c := range anySlice(ev["choices"]) {
				if delta, ok := c.(map[string]any)["delta"].(map[string]any); ok {
					if s, ok := delta["content"].(string); ok {
						b.WriteString(s)
					}
				}
			}
		}
		return b.String()
	}
	var doc map[string]any
	if json.Unmarshal(body, &doc) != nil {
		return ""
	}
	for _, c := range anySlice(doc["choices"]) {
		if msg, ok := c.(map[string]any)["message"].(map[string]any); ok {
			b.WriteString(strings.Join(collectText(msg["content"]), "\n"))
		}
	}
	for _, item := range anySlice(doc["output"]) {
		if m, ok := item.(map[string]any); ok {
			b.WriteString(strings.Join(collectText(m["content"]), "\n"))
		}
	}
	return b.String()
}

func anySlice(v any) []any {
	s, _ := v.([]any)
	return s
}

// screen runs one scan and decides. It returns a non-nil verdict when the
// traffic must be refused (injection found, or Vigil failed under "block").
func (g *gateway) screen(ctx context.Context, p *Policy, direction, text string) *injectionVerdict {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	if g.vigil == nil {
		if p.Injection.failOpen() {
			return nil
		}
		return &injectionVerdict{Direction: direction, Error: "vigil not configured"}
	}
	scanners, err := g.vigil.scan(ctx, text)
	if err != nil {
		injectionScans.WithLabelValues(direction, "error").Inc()
		if p.Injection.failOpen() {
			return nil
		}
		return &injectionVerdict{Direction: direction, Error: err.Error()}
	}
	if len(scanners) == 0 {
		injectionScans.WithLabelValues(direction, "clean").Inc()
		return nil
	}
	if n := len(p.Injection.counted(scanners)); n < p.Injection.minScanners() {
		injectionScans.WithLabelValues(direction, "warning").Inc()
		log.Printf("injection screening: %s flagged by %s (%d deciding scanner(s), %d needed); passed",
			direction, strings.Join(scanners, ", "), n, p.Injection.minScanners())
		return nil
	}
	injectionScans.WithLabelValues(direction, "injection").Inc()
	return &injectionVerdict{Direction: direction, Scanners: scanners}
}

// refuse answers with an OpenAI-style error, which OpenCode and other
// clients surface to the person instead of an empty reply.
func refuse(w http.ResponseWriter, v *injectionVerdict) {
	msg := "Occludra bloqueó el pedido: Vigil detectó un posible prompt injection"
	code := "prompt_injection"
	if v.Direction == "response" {
		msg = "Occludra bloqueó la respuesta del modelo: Vigil detectó un posible prompt injection"
	}
	if v.Error != "" {
		msg = "Occludra no pudo revisar el texto con Vigil y lo bloqueó por seguridad"
		code = "injection_scan_unavailable"
	}
	if len(v.Scanners) > 0 {
		msg += " (" + strings.Join(v.Scanners, ", ") + ")"
	}
	status := http.StatusForbidden
	if v.Error != "" {
		status = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{"message": msg, "type": "occludra_blocked", "code": code},
	})
}

func describeVerdict(v *injectionVerdict) string {
	if v.Error != "" {
		return v.Direction + " scan failed: " + v.Error
	}
	return v.Direction + " flagged by " + strings.Join(v.Scanners, ", ")
}

// externalClient is the client name Traefik stamps on requests that arrive
// from outside the cluster (manifests/ingress/llm-gateway.yaml). It
// overwrites whatever the caller sent, so outsiders cannot pose as ui-chat.
const externalClient = "external"

func splitTokens(raw string) []string {
	var out []string
	for _, t := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' }) {
		if t = strings.TrimSpace(t); len(t) >= 16 {
			out = append(out, t)
		}
	}
	return out
}

// externalAllowed checks the caller's bearer token against
// OCCLUDRA_EXTERNAL_TOKENS in constant time. No tokens configured: no
// external access.
func (g *gateway) externalAllowed(r *http.Request) bool {
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || got == "" {
		return false
	}
	match := false
	for _, want := range g.externalTokens {
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1 {
			match = true
		}
	}
	return match
}
