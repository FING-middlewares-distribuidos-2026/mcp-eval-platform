import { href } from "../router.ts";

interface Feature {
  name: string;
  question: string;
  link: { label: string; to: string };
  steps: { name: string; what: string }[];
}

const FEATURES: Feature[] = [
  {
    name: "Evaluar un MCP",
    question: "¿Este servidor MCP es seguro para conectarlo a un agente de IA?",
    link: { label: "Evaluar un MCP", to: href({ page: "servers" }) },
    steps: [
      {
        name: "Caja aislada",
        what: "El código del servidor se copia y se arranca en un contenedor sin internet. Solo puede hablar con los detectores de la plataforma.",
      },
      {
        name: "Vigil",
        what: "Lee todo lo que el servidor le diría a una IA (nombres y descripciones de herramientas, respuestas) y busca órdenes escondidas.",
      },
      {
        name: "Cuatro agentes",
        what: "Uno lee el código, otro lo prueba con pedidos raros, otro intenta que se porte mal y el último junta todo en un veredicto.",
      },
    ],
  },
  {
    name: "Tapar secretos",
    question: "¿Puedo usar un modelo sin pasarle mis contraseñas y tokens?",
    link: { label: "Chat protegido", to: href({ page: "chat" }) },
    steps: [
      {
        name: "Occludra",
        what: "Todo OpenCode que use la plataforma (el chat de acá o el tuyo, con la configuración que se muestra) habla con el modelo solo a través de Occludra.",
      },
      {
        name: "Detectores",
        what: "Antes de mandar nada, busca contraseñas, tokens, claves de API, emails y otros datos sensibles, en inglés y en castellano, y los reemplaza por [REDACTED].",
      },
    ],
  },
  {
    name: "Frenar prompt injection",
    question: "¿Alguien le está metiendo órdenes escondidas al modelo, o el modelo me devuelve algo armado para manipularme?",
    link: { label: "Registro de seguridad", to: href({ page: "security" }) },
    steps: [
      {
        name: "A la ida",
        what: "Vigil revisa el mensaje que sale hacia el modelo. Si encuentra un intento de manipularlo, Occludra no lo manda.",
      },
      {
        name: "A la vuelta",
        what: "La respuesta del modelo también pasa por Vigil antes de llegar a tu pantalla o a tu OpenCode. Si trae órdenes escondidas, no se muestra.",
      },
    ],
  },
];

export function HowItWorks() {
  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Cómo funciona</h1>
          <p className="page-lede">
            La plataforma hace tres cosas. Todo corre en un cluster de Kubernetes, y el modelo (Gemma 4 12B) en la GPU de una
            PC del equipo: nada se manda a un servicio en la nube.
          </p>
        </div>
      </header>

      {FEATURES.map((f, i) => (
        <section key={f.name} className="feature" aria-labelledby={`feature-${i}`}>
          <div className="feature-head">
            <span className="stage-n">{i + 1}</span>
            <div>
              <h2 id={`feature-${i}`}>{f.name}</h2>
              <p className="muted">{f.question}</p>
            </div>
            <a className="btn" href={f.link.to}>
              {f.link.label}
            </a>
          </div>
          <ol className="stages">
            {f.steps.map((s) => (
              <li key={s.name} className="stage panel">
                <h3>{s.name}</h3>
                <p>{s.what}</p>
              </li>
            ))}
          </ol>
        </section>
      ))}
    </div>
  );
}
