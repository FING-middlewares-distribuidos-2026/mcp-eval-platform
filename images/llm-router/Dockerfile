# syntax=docker/dockerfile:1.7
# llm-router: transparent LLM-endpoint redirector.
#
# Apps inside the container keep calling https://api.openai.com & friends;
# the entrypoint maps those hosts to 127.0.0.1 (container-local /etc/hosts)
# and this router answers TLS with a boot-generated CA, forwarding everything
# to the platform gateway (Occludra, via kubectl port-forward). Root on
# purpose: it must write /etc/hosts and refresh the system CA bundle.
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /llm-router .

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates curl procps \
    && rm -rf /var/lib/apt/lists/*

# kubectl (static binary, pinned) drives the self-healing port-forwards.
ARG KUBECTL_VERSION=v1.33.3
ARG KUBECTL_SHA256=2fcf65c64f352742dc253a25a7c95617c2aba79843d1b74e585c69fe4884afb0
RUN curl -fsSLo /usr/local/bin/kubectl \
      "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" \
    && echo "${KUBECTL_SHA256}  /usr/local/bin/kubectl" | sha256sum -c - \
    && chmod 0755 /usr/local/bin/kubectl

# netbird CLI (static binary, pinned) for the optional mesh. Stub today: the
# entrypoint only runs it when NETBIRD_* is configured.
ARG NETBIRD_VERSION=0.82.1
ARG NETBIRD_SHA256=c8f10b89dfa01b8bcad5ec25b666a83e351be4e22eb784b822478b9326a35423
RUN curl -fsSLo /tmp/netbird.tgz \
      "https://github.com/netbirdio/netbird/releases/download/v${NETBIRD_VERSION}/netbird_${NETBIRD_VERSION}_linux_amd64.tar.gz" \
    && echo "${NETBIRD_SHA256}  /tmp/netbird.tgz" | sha256sum -c - \
    && tar -xzf /tmp/netbird.tgz -C /usr/local/bin netbird \
    && chmod 0755 /usr/local/bin/netbird \
    && rm -f /tmp/netbird.tgz

COPY --from=build /llm-router /usr/local/bin/llm-router
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

# LLM_HOSTS lists what gets intercepted; anything else leaves the container
# untouched. OCCLUDRA_URL matches the entrypoint's port-forward to
# svc/occludra-service -n security-gateways.
ENV LLM_HOSTS=api.openai.com,api.anthropic.com,openrouter.ai,api.groq.com,gateway.ai.cloudflare.com,api.cohere.com,api.mistral.ai,opencode.ai \
    OCCLUDRA_URL=http://127.0.0.1:30080 \
    KUBECONFIG=/root/.kube/config

EXPOSE 443 8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
