import { relativeTime } from "../components/format.ts";
import type { Mode } from "../data/source.ts";
import { useGateway } from "../data/useGateway.ts";
import { type GatewayHop, detectorLabel, injectionSummary } from "../model/chat.ts";

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
  const entries = [...log.entries].reverse();
  const now = Date.now();
  const total = (pick: (h: GatewayHop) => number) => log.entries.reduce((a, h) => a + pick(h), 0);
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

      {mode === "demo" && <p className="notice">El registro es del cluster: cambiá a modo Cluster para verlo.</p>}
      {mode === "live" && log.state === "off" && (
        <p className="notice">Occludra no expone su registro en este cluster (falta OCCLUDRA_INSPECT_URL).</p>
      )}
      {mode === "live" && log.state === "error" && (
        <p className="notice notice-error" role="alert">
          {log.error} Reintentando…
        </p>
      )}

      {mode === "live" && (
        <dl className="tally" aria-label="Resumen">
          <div>
            <dt>Mensajes al modelo</dt>
            <dd>{log.entries.length}</dd>
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
