import { relativeTime } from "../components/format.ts";
import type { Mode } from "../data/source.ts";
import { useGateway } from "../data/useGateway.ts";
import { type GatewayHop, detectorLabel, injectionSummary } from "../model/chat.ts";

/** Shown in demo mode only, labelled as examples: what each kind of row looks like. */
function exampleEntries(now: number): GatewayHop[] {
  const at = (minAgo: number) => new Date(now - minAgo * 60_000).toISOString();
  const base = { requestBytes: 900, responseBytes: 400, upstream: "10.147.17.21:8080", servedBy: "primary", model: "gemma-4-12b-it" };
  return [
    { ...base, id: 1, at: at(42), client: "ui-chat", redactions: {}, status: 200, durationMs: 4200 },
    { ...base, id: 2, at: at(31), client: "ui-chat", redactions: { "password-context": 1, "api-key": 1 }, status: 200, durationMs: 5100 },
    {
      ...base, id: 3, at: at(18), client: "external", redactions: {}, status: 403, durationMs: 1300,
      blockedBy: "vigil:request", injection: { direction: "request", scanners: ["YARA signature(s)", "transformer model"] },
    },
    { ...base, id: 4, at: at(9), client: "external", redactions: { email: 2 }, status: 200, durationMs: 6900 },
    {
      ...base, id: 5, at: at(3), client: "ui-chat", redactions: {}, status: 403, durationMs: 7400,
      blockedBy: "vigil:response", injection: { direction: "response", scanners: ["vector similarity"] },
    },
  ];
}

const CLIENT_LABEL: Record<string, string> = {
  "ui-chat": "Chat de la UI",
  external: "OpenCode externo",
};

function masked(hop: GatewayHop): string {
  const parts = Object.entries(hop.redactions).map(([k, n]) => `${n} ${detectorLabel(k)}`);
  return parts.length ? parts.join(", ") : "nada";
}

function vigil(hop: GatewayHop): { text: string; tone: string } {
  if (!hop.injection) return { text: hop.blockedBy ? "—" : "sin problemas", tone: "t-safe" };
  return { text: injectionSummary(hop) ?? "", tone: hop.injection.error ? "t-caution" : "t-bad" };
}

/** Everything Occludra and Vigil did for the protected chat and for external OpenCode clients. */
export function SecurityPage({ mode }: { mode: Mode }) {
  const log = useGateway(mode === "live");
  const now = Date.now();
  const demo = mode === "demo";
  const source = demo ? exampleEntries(now) : log.entries;
  const entries = [...source].reverse();
  const total = (pick: (h: GatewayHop) => number) => source.reduce((a, h) => a + pick(h), 0);
  const maskedTotal = total((h) => Object.values(h.redactions).reduce((a, b) => a + b, 0));
  const outbound = total((h) => (h.injection?.direction === "request" && !h.injection.error ? 1 : 0));
  const inbound = total((h) => (h.injection?.direction === "response" && !h.injection.error ? 1 : 0));

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Registro de seguridad</h1>
          <p className="page-lede">
            Cada mensaje que un OpenCode le mandó al modelo a través de la plataforma, y qué hicieron con él Occludra (datos
            tapados) y Vigil (prompt injection a la ida y a la vuelta). Se guarda solo lo que pasó, nunca el texto.
          </p>
        </div>
      </header>

      {demo && (
        <p className="notice">Estas filas son ejemplos de lo que aparece acá. En modo Cluster ves el registro real.</p>
      )}
      {mode === "live" && log.state === "off" && (
        <p className="notice">Occludra no expone su registro en este cluster (falta OCCLUDRA_INSPECT_URL).</p>
      )}
      {mode === "live" && log.state === "error" && (
        <p className="notice notice-error" role="alert">
          {log.error} Reintentando…
        </p>
      )}

      {(demo || log.state === "ready") && (
        <dl className="tally" aria-label="Resumen">
          <div>
            <dt>Mensajes al modelo</dt>
            <dd>{source.length}</dd>
          </div>
          <div>
            <dt>Datos tapados</dt>
            <dd>{maskedTotal}</dd>
          </div>
          <div>
            <dt>Injection frenados a la ida</dt>
            <dd className={outbound ? "t-bad" : undefined}>{outbound}</dd>
          </div>
          <div>
            <dt>Injection frenados a la vuelta</dt>
            <dd className={inbound ? "t-bad" : undefined}>{inbound}</dd>
          </div>
        </dl>
      )}

      {mode === "live" && log.state === "ready" && entries.length === 0 && (
        <p className="empty">
          Todavía no pasó nada por el gateway. Mandá un mensaje desde <a href="#/chat">Chat protegido</a> o desde tu
          OpenCode.
        </p>
      )}

      {entries.length > 0 && (
        <div className="seclog-wrap">
          <table className="seclog">
            <thead>
              <tr>
                <th scope="col">Cuándo</th>
                <th scope="col">Desde</th>
                <th scope="col">Occludra tapó</th>
                <th scope="col">Vigil</th>
                <th scope="col">Resultado</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((h) => {
                const v = vigil(h);
                return (
                  <tr key={h.id}>
                    <td title={h.at}>{relativeTime(h.at, now)}</td>
                    <td>{CLIENT_LABEL[h.client] ?? h.client}</td>
                    <td>{masked(h)}</td>
                    <td className={v.tone}>{v.text}</td>
                    <td>
                      {h.status < 400 ? "respondió" : h.injection ? "bloqueado" : `error ${h.status}`}
                      <span className="row-sub">{(h.durationMs / 1000).toFixed(1)} s</span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
