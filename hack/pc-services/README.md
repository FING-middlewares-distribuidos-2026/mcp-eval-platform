# pc-services — what the GPU PC serves to the cluster, by API

The PC is **not** a cluster node. It runs two APIs in Docker, listening only
on its ZeroTier address, and the k0s cluster calls them:

```
 k0s cluster (ZeroTier 10.147.17.0/24)                    GPU PC (10.147.17.21)
 ┌──────────────────────────────────────┐                ┌──────────────────────────────┐
 │ Occludra ── Bearer LOCAL_LLM_API_KEY ─┼──── :8080 ────▶│ llm   llama.cpp, Gemma (GPU) │
 │                                      │                │                              │
 │ operator / evaluator / Occludra      │                │ vigil-auth  nginx: token +   │
 │   └▶ vigil-service:5000              │                │   /analyze/{prompt,response} │
 │        vigil relay (nginx) ─ Bearer ─┼──── :5000 ────▶│   └▶ vigil  scanner (CPU)    │
 │                                      │                │        │                     │
 │ Traefik /chroma ─▶ chroma-gateway ◀──┼── :31365 ──────┼────────┘ reader token        │
 └──────────────────────────────────────┘   (NodePort)   └──────────────────────────────┘
```

- **llm** — llama.cpp's OpenAI-compatible server on the GPU. Occludra is
  its only caller (`LOCAL_LLM_URL` in `deploy/k0s/render.env`).
- **vigil** — the prompt-injection scanner: the same image and `server.conf`
  the cluster ran (`manifests/vigil-deployment.yaml`), our YARA rules, and
  the corpus read from the cluster's Chroma through Traefik. Not published.
- **vigil-auth** — nginx in front of Vigil: checks the bearer token and lets
  only the two scan calls (and `GET /ready` for the relay's probe) through.
- In the cluster, `manifests/vigil-remote.yaml` keeps `vigil-service`, now a
  relay that adds the token. Nothing that calls Vigil changed.

PC off → the relay is not ready → scans fail and evaluations and the chat
**fail closed**, as before.

## Use

```bash
hack/pc-services/pc up          # LLM + Vigil, waits until healthy
hack/pc-services/pc up vigil    # just one group: llm | vigil
hack/pc-services/pc status
hack/pc-services/pc smoke       # one call to each API through its token check
hack/pc-services/pc logs vigil
hack/pc-services/pc down
```

Nothing starts at boot (`restart: "no"`). First start of Vigil downloads its
classifier and embedder (~1.5 GB) into `~/.cache/mcp-eval/pc-services/`.

## Setup (once)

1. `cp hack/pc-services/pc.conf.example hack/pc-services/pc.conf` if any
   default does not fit (ZeroTier IP, model path, Chroma entry point).
2. Tokens, in `~/.config/mcp-eval/` (0600), written by
   `CONTEXT=k0s hack/gitops/secrets.sh deploy/k0s`:
   - `local-llm.key` — the LLM's API key (also in Occludra's Secret);
   - `vigil-api-token` — Vigil's token (also in Secret `vigil-remote-token`);
   - `chroma-reader-token` — Chroma's reader token, copied from the cluster;
   - `ingress-cert.pem` — the ingress certificate, to verify Traefik.

## Why Chroma goes through a NodePort

The ingress IP 10.66.51.11 is routed from the PC by the university's
ZeroTier gateway, which goes down. The PC instead enters Traefik on a node's
address in the platform's own ZeroTier network (`CHROMA_URL`, NodePort fixed
in `manifests/traefik/values-mcp-eval.yaml`) and still verifies the
certificate issued for 10.66.51.11 (`[vectordb] ca_file` and
`tls_server_name` in `images/vigil-llm/remote_vectordb.py`).
