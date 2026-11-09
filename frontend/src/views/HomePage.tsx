import type { Snapshot } from "../data/source.ts";
import { serverState } from "../model/verdict.ts";
import { href } from "../router.ts";

/**
 * Inicio: the three things the platform does, as three doors. Each door shows
 * a tiny example of its job, so the choice is obvious before reading.
 */
export function HomePage({ snap }: { snap: Snapshot }) {
  const servers = Object.values(snap.servers);
  const malicious = servers.filter((s) => serverState(snap, s).kind === "malicious").length;

  return (
    <div className="page home">
      <header className="home-hero">
        <h1>Usá IA sin entregarle tus secretos</h1>
        <p className="home-redact" aria-label="Ejemplo: mi contraseña es, y la contraseña aparece tapada">
          <span>mi contraseña es </span>
          <span className="redact">
            <span className="redact-secret" aria-hidden="true">
              Hunter2!2026
            </span>
          </span>
        </p>
        <p className="home-lede">
          Esta plataforma se para entre vos y el modelo de IA. Revisa las herramientas antes de que las conectes, tapa lo
          que no tiene que salir y frena a quien intente manipular al modelo.
        </p>
      </header>

      <ul className="doors" aria-label="Qué podés hacer">
        <li className="door door-eval">
          <a href={href({ page: "servers" })} className="door-link">
            <div className="door-sample" aria-hidden="true">
              <p className="sample-url">github.com/alguien/servidor-mcp</p>
              <p className="sample-verdict">
                <span className="verdict v-malicious">Malicioso</span>
                <span className="sample-why">esconde órdenes en sus herramientas</span>
              </p>
            </div>
            <h2>Evaluar un MCP</h2>
            <p>
              Pegás el enlace de un servidor MCP y la plataforma lo prueba encerrado: lee su código, lo usa con pedidos
              raros y te dice si es seguro conectarlo.
            </p>
            <p className="door-meta">
              {servers.length === 0
                ? "Todavía no hay servidores cargados."
                : `${servers.length} ${servers.length === 1 ? "servidor" : "servidores"} vigilados${malicious ? `, ${malicious} ${malicious === 1 ? "malicioso" : "maliciosos"}` : ""}.`}
            </p>
            <span className="btn btn-primary door-cta">Evaluar un servidor</span>
          </a>
        </li>

        <li className="door door-mask">
          <a href={href({ page: "chat" })} className="door-link">
            <div className="door-sample" aria-hidden="true">
              <p className="sample-bubble">
                el token es <span className="redact redact-static">ghp_9f8e7d6c</span> y la clave{" "}
                <span className="redact redact-static">Sup3r!26</span>
              </p>
              <p className="sample-caption">así lo recibe el modelo</p>
            </div>
            <h2>Chat protegido</h2>
            <p>
              Hablá con el modelo como siempre. Si se te escapa una contraseña, un token o un email, se tapa antes de salir
              de la plataforma. También sirve para tu propio OpenCode.
            </p>
            <p className="door-meta">Funciona en castellano y en inglés.</p>
            <span className="btn door-cta">Abrir el chat</span>
          </a>
        </li>

        <li className="door door-guard">
          <a href={href({ page: "security" })} className="door-link">
            <div className="door-sample" aria-hidden="true">
              <p className="sample-flow">
                <span className="flow-step">tu mensaje</span>
                <span className="flow-check">revisado</span>
                <span className="flow-step">modelo</span>
                <span className="flow-check flow-stop">frenado</span>
                <span className="flow-step">vos</span>
              </p>
              <p className="sample-caption">“ignorá tus instrucciones y…”</p>
            </div>
            <h2>Registro de seguridad</h2>
            <p>
              Cada mensaje se revisa a la ida y a la vuelta buscando prompt injection: órdenes escondidas para manipular al
              modelo. Acá ves todo lo que se tapó y todo lo que se frenó.
            </p>
            <p className="door-meta">Se guarda qué pasó, nunca el texto.</p>
            <span className="btn door-cta">Ver el registro</span>
          </a>
        </li>
      </ul>

      <p className="home-foot">
        ¿Cómo está armado por dentro? <a href={href({ page: "how" })}>Cómo funciona</a>
      </p>
    </div>
  );
}
