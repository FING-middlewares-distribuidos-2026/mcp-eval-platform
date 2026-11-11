#!/usr/bin/env bash
# llm-router container entrypoint.
#
#   1. map every LLM_HOSTS host to 127.0.0.1 in THIS container's /etc/hosts
#      (container-local only — the host's /etc/hosts is never touched)
#   2. keep kubectl port-forwards to the in-cluster gateway (and vigil, for
#      diagnostics) alive with retry loops
#   3. netbird mesh, only if NETBIRD_SETUP_KEY + NETBIRD_MANAGEMENT_URL are
#      both set; otherwise one honest log line
#   4. run the router in the foreground while bash stays PID 1 and reaps the
#      background loops (Go does not reap orphaned kubectl processes)
set -eu

LLM_HOSTS="${LLM_HOSTS:-api.openai.com,api.anthropic.com,openrouter.ai,api.groq.com,gateway.ai.cloudflare.com,api.cohere.com,api.mistral.ai,opencode.ai}"
OCCLUDRA_URL="${OCCLUDRA_URL:-http://127.0.0.1:30080}"
KUBECONFIG="${KUBECONFIG:-/root/.kube/config}"
START_PORT_FORWARDS="${START_PORT_FORWARDS:-1}"
LLM_ROUTER_BIN="${LLM_ROUTER_BIN:-/usr/local/bin/llm-router}"
export KUBECONFIG

log() { printf '[entrypoint] %s\n' "$*" >&2; }

# --- 1. container-local hosts file -------------------------------------
# Appends (never rewrites: /etc/hosts is a docker bind mount where sed -i
# fails with EBUSY). gethostbyname takes the FIRST match, so a host mapped
# by --add-host would win over us; don't do that for LLM_HOSTS hosts.
map_hosts() {
  local host first=1
  local IFS=','
  # shellcheck disable=SC2086  # LLM_HOSTS is a comma list; word-split intended
  for host in $LLM_HOSTS; do
    host="${host// /}"
    [ -n "$host" ] || continue
    local esc="${host//./\\.}" # dots are regex metachars
    if grep -Eq "^[^#]*[[:space:]]${esc}([[:space:]]|\$)" /etc/hosts 2>/dev/null; then
      [ "$first" = 1 ] || continue
      log "hosts: '$host' already mapped in /etc/hosts (first match wins; not overriding)"
      first=0
      continue
    fi
    printf '127.0.0.1\t%s\n' "$host" >> /etc/hosts
    log "hosts: $host -> 127.0.0.1"
    first=0
  done
}

# --- 2. self-healing port-forwards -------------------------------------
# kubectl port-forward dies silently (context deadlines, API restarts); the
# loop revives it. The FIRST attempt logs to stderr so a broken kubeconfig is
# visible; later attempts are silenced to keep the logs readable.
port_forward_loop() {
  local what="$1" ns="$2" svc="$3" mapping="$4"
  log "port-forward: $what (svc/$svc -n $ns) -> 127.0.0.1 ${mapping%%:*}"
  (
    local attempt=0
    while true; do
      attempt=$((attempt + 1))
      if [ "$attempt" -eq 1 ]; then
        kubectl -n "$ns" port-forward "svc/$svc" "$mapping" >&2 || true
      else
        kubectl -n "$ns" port-forward "svc/$svc" "$mapping" >/dev/null 2>&1 || true
      fi
      sleep 3
    done
  ) &
}

# --- 3. netbird (optional mesh; stub until the netbird namespace exists)
maybe_netbird() {
  if [ -n "${NETBIRD_SETUP_KEY:-}" ] && [ -n "${NETBIRD_MANAGEMENT_URL:-}" ]; then
    if ! command -v netbird >/dev/null 2>&1; then
      log "netbird: binary missing; mesh no desplegado — usando port-forwards"
      return 0
    fi
    log "netbird: joining mesh ${NETBIRD_MANAGEMENT_URL} (daemon + up, never blocks startup)"
    # netbird >=0.4x: `up` is a thin CLI over a unix-socket daemon — the
    # daemon must be installed/started first (the official image does this
    # in its own entrypoint).
    (
      netbird service install >/dev/null 2>&1 || true
      netbird service start  >/dev/null 2>&1 || true
      sleep 5
      while true; do
        # shellcheck disable=SC2086  # NETBIRD_EXTRA_ARGS is deliberately word-split
        netbird up --management-url "$NETBIRD_MANAGEMENT_URL" \
          --setup-key "$NETBIRD_SETUP_KEY" ${NETBIRD_EXTRA_ARGS:-} \
          >/dev/null 2>&1 || true
        sleep 10
      done
    ) &
  else
    log "netbird: mesh no desplegado — usando port-forwards"
  fi
}

map_hosts

if [ "$START_PORT_FORWARDS" = 1 ] && [ -f "$KUBECONFIG" ]; then
  port_forward_loop occludra security-gateways occludra-service 30080:8080
  port_forward_loop vigil security-gateways vigil-service 30500:5000
elif [ "$START_PORT_FORWARDS" = 1 ]; then
  log "kubeconfig $KUBECONFIG not mounted; port-forwards off (point OCCLUDRA_URL at the gateway another way)"
else
  log "port-forwards disabled (START_PORT_FORWARDS=0)"
fi

maybe_netbird

log "starting router: ${LLM_HOSTS} -> ${OCCLUDRA_URL}"
"$LLM_ROUTER_BIN" &
router_pid=$!
trap 'kill -TERM "$router_pid" 2>/dev/null || true' TERM INT
wait "$router_pid"
trap - TERM INT
wait # reap the background loops before exiting with the router's status
