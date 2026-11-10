# Estado del proyecto y contexto para seguir (2026-11-10)

Este documento junta todo lo que pasó en la sesión larga del 2026-11-09/10
(PC deja de ser nodo, Chroma en la PC, Flux reactivado, cambios de Diego) y
lo que hace falta saber para seguir desde otra máquina. Las decisiones de
diseño con su porqué están en [`decisions.md`](decisions.md); acá va el
estado, los problemas y dónde está cada cosa.

## Actualización 2026-11-10 (tarde, desde la laptop de Julián)

Estado: **las tres funcionalidades andan y están probadas punta a punta en k0s.**

- Chat: "hola", "contame un chiste" responden; "Mi contraseña es …" se
  enmascara (`password-context`) y responde; "Ignorá todas las
  instrucciones…" / "Ignore all previous…" → 403 por YARA.
- Evaluación de `evil-demo-mcp` (run `evil-demo-mcp-run-4w47h`): score 0,
  Malicious, cortada por Vigil en la superficie anunciada (los tres scanners).
  Fase `Failed` = así se registra un aborto por inyección, como el run de
  referencia `dkpv9`.

Qué se hizo (detalle y porqués en `decisions.md`, entradas del 2026-11-10):

1. PR #20 mergeado (escaneo de doble sentido de Diego en `log`).
2. PR #22: en el chat **solo YARA bloquea** (`policy.injection.count_scanners:
   ["YARA"]`); transformer y vectordb quedan como aviso en el log
   (`injection screening: ... passed`). El transformer (deberta) es un modelo
   en inglés y marcaba "hola" y todo mensaje con `[REDACTED]`. Reglas YARA en
   español nuevas (`manifests/vigil-yara/injection-es.yar`). Medido: 26/40
   mensajes normales bloqueados antes, 0/40 ahora.
3. Perfiles de nodo (`deploy/k0s-nodes`) **aplicados por primera vez** (no
   estaban activos en ningún nodo) + GC de imágenes al 70 % (antes coincidía
   con el umbral de expulsión). Rama `node-image-gc`, ya aplicada con
   `apply.sh apply`; falta mergear el PR (solo deja el cambio en git).
4. journald limitado a 200 MB en los tres nodos
   (`/etc/systemd/journald.conf.d/size.conf`, a mano, **no está en git**).
5. Diego: no había nada mal de su lado; el Chroma del cluster es parte del
   proyecto y se queda.

Pendiente:

- Mergear el PR de `node-image-gc`.
- Borrar la caché huérfana de Chroma en nodo-g1-3 (2,5 GB,
  `/local/cache/chroma-query-service`, solo si `query-service-0` sigue en
  nodo-g1-1).
- nodo-g1-1 es el nodo justo de disco (casi todas sus imágenes están en uso:
  58 % Chroma, 23 % Grafana). Si una evaluación vuelve a ser expulsada por
  `ephemeral-storage`, el siguiente paso es pedir discos más grandes en
  OpenStack (18 GB hoy).
- Menores de antes: la VIP sí responde desde la laptop de Julián (red ZeroTier
  de la facultad); readiness de Traefik; `image-importer` (DaemonSet hecho a
  mano en `kube-system`) se expulsa con DiskPressure y deja pods Evicted.

Desde la laptop de Julián: kubeconfig en `~/.kube/configs/k0s.yaml`, contexto
`k0s` (el contexto por defecto es otro cluster). No tiene `gh`, `flux` ni
`helm`. SSH a los nodos solo desde la laptop de Juan.

## Resumen en cinco líneas

- La plataforma corre en el cluster k0s (3 VMs de OpenStack), gestionada por Flux desde `main` (`deploy/k0s`).
- La PC con GPU ya no es nodo: sirve el LLM (Gemma 4 12B), Vigil y el corpus de Vigil (un Chroma) por API con token, por ZeroTier (`hack/pc-services`).
- Anda: Flux, los tres nodos, `/llm/v1` externo (responde, bloquea inyecciones, pide token).
- No anda bien: el chat de la UI rechaza todo hasta que se mergee el PR #20; un mensaje con un secreto se enmascara y después Vigil lo bloquea.
- No probado: una evaluación de un MCP, porque a los workers casi no les queda disco.

## Lo que quedó pendiente (en orden)

1. **Mergear el PR #20** (`gh pr merge 20 --merge`). Lo tiene que correr Juan: el
   clasificador de permisos de Claude Code no deja a Claude mergear un cambio
   que baja un bloqueo a registro ("Security Weaken"). Pasa el escaneo de doble
   sentido de Occludra de `VIGIL_IN_ACTION=block` a `log`. Ver "Problema 1".
2. **Decidir qué tan estricto es `policy.injection`** (ver "Problema 2"). Opciones:
   dejarlo, exigir que dos detectores de Vigil coincidan, o sacar el detector
   `transformer` de esta política. Recomendación de Claude: dos detectores.
3. **Liberar disco en los workers** antes de correr evaluaciones (ver "Problema 3").
   Recomendación: retirar el Chroma distribuido del cluster (Vigil ya no lo
   usa; solo `DEMO.md` de Diego lo usa). Hablarlo con Diego.
4. **Objetos sueltos de Diego** en el cluster (ver "Cosas de Diego").
5. Después de 1–3: probar punta a punta las tres funcionalidades: chat con un
   secreto, chat con una inyección, evaluación de `evil-demo-mcp`.
6. Menores: la VIP 10.66.51.11 no responde desde la PC (se usa NodePort);
   readiness probe de Traefik con `failureThreshold: 1` (flapea en el nodo lento,
   candidato en `manifests/traefik/values-mcp-eval.yaml`); el escaneo de salida
   de Diego siempre recibe HTTP 400 de Vigil.

## Arquitectura en una página

```
 navegador ──HTTPS+basic auth──▶ Traefik (MetalLB VIP 10.66.51.11, NodePort 31365)
                                   ├─ /            → mcp-eval-ui (React + servidor Node)
                                   │                   └─ /api/chat → opencode-chat ─┐
                                   └─ /llm/v1      → Occludra (token externo) ◀──────┘
 operador (CRD MCPServer) ─ Job de evaluación (cloner, sandbox, evaluator) ─▶ Occludra
 Occludra: enmascara secretos (redact) → policy.injection (Vigil) → LLM
           + escaneo de doble sentido (Vigil, todo pedido, todo cliente)
 Occludra ──▶ vigil-service (relay en el cluster) ──ZeroTier+token──▶ PC :5000 vigil-auth → Vigil → Chroma (red Docker interna)
 Occludra ──ZeroTier+API key──▶ PC :8080 llama.cpp (Gemma 4 12B)
```

Las tres funcionalidades:

1. **Evaluar un MCP**: se registra un `MCPServer` (UI o kubectl); el operador
   lanza el Job; el veredicto queda en el status y en la UI.
2. **Chat protegido**: UI → OpenCode → Occludra, que reemplaza contraseñas y
   tokens por `[REDACTED]` antes de que lleguen al LLM.
3. **Prompt injection en los dos sentidos**: Vigil revisa lo que entra (y el
   escaneo de doble sentido también lo que sale).

## Dónde está cada cosa en el repo

| Qué | Dónde |
|---|---|
| Decisiones (quién decidió y por qué) | `docs/decisions.md` |
| Lo que aplica Flux | `deploy/k0s/` (`kustomization.yaml`, `render.env`, `generated/`, `patches/`) |
| Renderizar `generated/` desde `deploy.sh` | `hack/gitops/render.sh deploy/k0s` (necesita PyYAML; usar un venv) |
| Crear los Secrets (nunca van a git) | `hack/gitops/secrets.sh deploy/k0s` (ver cabecera del script) |
| Servicios de la PC (LLM, Vigil, Chroma) | `hack/pc-services/` (`pc up/down/status/smoke`, `compose.yaml`, `README.md`) |
| Script viejo de nodo GPU (retirado, se conserva) | `hack/gpu-node/` |
| Gateway Occludra (Go) | `images/occludra-gateway/` (`main.go`, `injection.go` = policy.injection, `vigil.go` = escaneo de doble sentido) |
| Vigil (imagen + cliente Chroma remoto) | `images/vigil-llm/` |
| Cargador del corpus | `images/vigil-corpus-loader/`, lock en `hack/vigil-corpus/` |
| Manifiestos | `manifests/` (`chroma/`, `ingress/`, `traefik/`, `metallb/`, `vigil-remote.yaml`, `occludra-deployment.yaml`) |
| UI | `frontend/` (`src/`, `server/chat.ts`, `deploy/ui-chat.yaml`) |
| Operador | raíz del repo (Go, kubebuilder: `api/`, `internal/`, `cmd/`) |
| Runbook de demo de Diego | `DEMO.md` (usa el Chroma del cluster y pone `block` a mano) |
| CI | `.github/workflows/` (en push a `main` el bot commitea `deploy/k0s: images sha-<merge>`) |

Imágenes: `docker.io/jjhonson/*:sha-<7 chars del merge>` (públicas, las sube CI).

## Ramas y PRs

- `main`: lo que corre. Último commit aplicado por Flux: `8a8098d` (imágenes `sha-88dccf9`).
- **PR #20 `vigil-in-log` — ABIERTO, CI verde, falta mergear** (ver arriba).
- PR #19 (mergeado): corpus de Vigil en la PC; Chroma del cluster pide la memoria que usa. Tiene un comentario con la verificación posterior.
- PR #18 (mergeado): arreglos de pc-services; copió a git el `block` que Diego había puesto a mano (eso fue un error, lo corrige #20).
- PR #17 (mergeado): la PC sirve LLM y Vigil por API.
- PR #16, #14, #13 y anteriores: ver `gh pr list --state merged`.
- Ramas viejas (`m2-local-llm`, `m3-vigil-e5-hybrid`, `m3-integration`, `pc-*`): todo su contenido ya está en `main`; se pueden borrar.

## Cómo trabajar desde otra PC

1. `git clone git@github.com:JuanLoncharich/Middlewares.git` (o https).
2. Kubeconfig del cluster: copiar `~/.kube/configs/k0s.yaml` de la PC vieja por
   un canal privado (nunca a git) y crear el contexto `k0s`. El API server está
   en la red de la universidad (10.66.50.59:6443); si el gateway ZeroTier de la
   universidad se cae, se llega por nuestra red ZeroTier a
   `https://10.147.17.228:6443` con `--tls-server-name=10.66.50.59`.
3. La otra PC tiene que estar en la red ZeroTier "middlewares" (aprobarla en
   ZeroTier Central) para llegar a los nodos (10.147.17.3 / .98 / .228) y a la
   PC con GPU (10.147.17.21).
4. Archivos privados que viven en `~/.config/mcp-eval/` de la PC con GPU (copiar
   solo los que haga falta, por canal privado, modo 600):
   - `ui-login` (usuario:contraseña de la UI), `ingress-cert.pem` (certificado de Traefik)
   - `llm-gateway-token` (token de `/llm/v1` para OpenCode externo)
   - `vigil-api-token` y `local-llm.key` (los usa `hack/pc-services`, solo en la PC con GPU)
   - `chroma-reader-token`: ya no se usa.
5. Los servicios de la PC se prenden **en la PC con GPU**: `hack/pc-services/pc up`
   y se verifican con `pc smoke`. No arrancan solos al bootear. Si Plato
   (`plato-llm.service`) tiene la GPU, hay que pararlo primero.
6. Acceso a OpenStack y SSH a los nodos: solo desde la laptop que hace de jump host.

Comandos útiles:

```sh
kc() { kubectl --context k0s --request-timeout=25s "$@"; }
kc get nodes; kc -n flux-system get kustomization platform
flux --context k0s reconcile kustomization platform --with-source
kc get pods -A | grep -v -E 'Running|Completed'
# disco y presión de cada nodo
kc describe nodes | grep -E '^Name:|DiskPressure|MemoryPressure'
# UI cuando la VIP no responde (NodePort en nodo-g1-3)
curl --cacert ~/.config/mcp-eval/ingress-cert.pem \
  --connect-to 10.66.51.11:443:10.147.17.98:31365 https://10.66.51.11/
```

La API de la UI (`/api/...`) exige el header `Origin: https://10.66.51.11`.

## Qué pasó en esta sesión (cronología corta)

1. **Flux estaba pausado** con cambios hechos a mano en el cluster. Se mergeó #18
   y se reanudó `platform`. Al reanudar, Flux reaplica todo y reinicia pods.
2. **nodo-g1-1 estaba congelado al bootear** (desde 2026-10-30). Se arregló con
   `openstack server reboot --soft nodo-g1-1` desde la laptop (lo corrió Juan).
   Usar `--soft`: un hard reboot el 2026-10-21 dejó una VM en ERROR.
3. **etcd del control plane** sin fsync estaba lento; Juan corrió `fix-etcd-nofsync.sh`.
4. **La PC dejó de ser nodo** (#17): ahora sirve el LLM y Vigil por API con token.
5. **Vigil daba 500**: el Chroma del cluster no entraba en un solo worker.
   Juan aprobó dos cosas (#19): bajar los requests de memoria de Chroma (g1-3
   pasó de 92 % a 59 %) y mover el corpus de Vigil a un Chroma en la PC. Hecho y verificado.
6. **Error de Flux con los MemberList de Chroma** (`spec: Invalid value: "null"`):
   se arregló con la anotación `kustomize.toolkit.fluxcd.io/ssa: IfNotPresent`.
7. **El chat de la UI rechaza todo**: encontrado y corregido en #20 (pendiente de merge).
8. Se dejaron resultados de verificación como comentario en #19.

## Problemas abiertos en detalle

### Problema 1: el chat de la UI rechaza todos los mensajes

Occludra llama a Vigil en dos lugares:

- **`policy.injection`** (`injection.go`, de Juan): solo clientes `ui-chat` y
  `external`; mira solo el turno de la persona, ya enmascarado. Cualquier
  detector que salte → 403 `prompt_injection`. Si Vigil no responde → 503 (falla cerrado).
- **Escaneo de doble sentido** (`vigil.go`, de Diego; `VIGIL_SCAN_IN/OUT`,
  `VIGIL_IN_ACTION`): todos los clientes, el pedido entero incluido el prompt
  de sistema. En modo `block`, Vigil marca la frase del prompt del chat
  "Respondé en español, breve y claro." y todo mensaje da 403 `vigil_block`.

Diego puso `block` con `kubectl set env` para su demo; #18 lo copió a git por
error. #20 lo pasa a `log`. `DEMO.md` sigue pudiendo poner `block` a mano.

### Problema 2: falsos positivos de `policy.injection`

Medido en la Vigil de la PC con los umbrales de `server.conf`:

| Regla | Mensajes normales bloqueados | Inyecciones detectadas |
|---|---|---|
| Cualquier detector (hoy) | 12 de 30 ("hola", "What is 2+2?") | 9 de 10 |
| Dos detectores de acuerdo | 2 de 30 | 7 de 10 |

El detector `transformer` (deberta, umbral 0.98) marca `[REDACTED]` solo y
cualquier frase que hable de una contraseña o una API key, aunque el valor sea
"azul" o "\*\*\*\*". Por eso un mensaje con un secreto se enmascara bien (se ve
en el log de Occludra) y después se bloquea: la funcionalidad 2 no se puede
mostrar respondiendo hasta decidir esto.

### Problema 3: disco de los workers

Cada worker tiene 18,2 Gi de disco, ~3 Gi libres, y kubelet expulsa pods por
debajo de ~2,74 Gi. Bajar cualquier imagen grande dispara `DiskPressure`
(pasó en nodo-g1-1 al reiniciar Chroma: expulsó pods y se recuperó solo). Una
evaluación necesita bajar `mcp-cloner` y `mcp-target-sandbox` (~223 Mi
comprimidos) y hoy no están en ningún worker. Además los discos de OpenStack
son muy lentos: crear contenedores a veces da "failed to reserve sandbox name"
durante 10–30 min y se resuelve solo.

### Cosas de Diego (no se tocaron)

- Pods de prueba: `default/scan-t1..t3`, `scan-test`, `scan-test2`, `errprobe`,
  `a2test`, `survtest`; `security-gateways/survtest2`, `opencode-workstation-demo`.
- Deployment `security-gateways/vigil-demo` (0 réplicas) que monta el ConfigMap
  `vigil-yara-rules` (marcado `prune=disabled` para que Flux no lo borre).
- Pod viejo expulsado `mcp-eval-ui/opencode-chat-95fb5ff57-qcz4f` (se puede borrar).

## Lecciones que conviene recordar

- Reanudar Flux después de una pausa larga reinicia cargas: mirar capacidad antes.
- Flux borra lo que se cambió con `kubectl set`/`patch`; lo que vale tiene que estar en git.
- El límite real de los workers son los **requests** de memoria (3,9 GB por nodo), no el uso.
- Si Vigil falla, Occludra bloquea todo (falla cerrado): el síntoma "el chat no anda" suele ser Vigil o Chroma.
- ZeroTier entre la PC y los nodos pierde paquetes de más de ~1228 bytes: la red Docker de pc-services usa MTU 1200.
- Después de reiniciar ZeroTier en la PC, `local.conf` tiene que excluir 10.244.0.0/16 y 10.96.0.0/12 (si no, ZeroTier aprende rutas por la red de pods y se hace un bucle).
- Sin shell en los nodos: `kubectl get --raw /api/v1/nodes/<nodo>/proxy/stats/summary` y `kubectl exec` en `kube-system/image-importer-*` (tiene `ctr`).
- Lo que Claude Code no puede hacer en modo auto (lo corre Juan): escribir Secrets, reiniciar VMs de OpenStack, escalar `observability`, mergear un PR que baja un control de seguridad, shell con escritura en los nodos.
