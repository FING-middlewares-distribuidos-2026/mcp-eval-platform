// Shapes shared by the chat backend (server/chat.ts) and the chat view.

/** One inference request as Occludra's journal records it: metadata, never content. */
export interface GatewayHop {
  id: number;
  at: string;
  client: string;
  model?: string;
  redactions: Record<string, number>;
  blockedBy?: string;
  status: number;
  /** host:port of the upstream model server. */
  upstream?: string;
  servedBy?: string;
  durationMs: number;
  requestBytes: number;
  responseBytes: number;
  /** Set when Vigil screened the call and Occludra refused it (or could not scan). */
  injection?: InjectionVerdict;
}

/** Occludra's prompt-injection decision (images/occludra-gateway/injection.go). */
export interface InjectionVerdict {
  /** "request": the message going to the model; "response": the model's answer. */
  direction: "request" | "response";
  scanners?: string[];
  error?: string;
}

export interface ChatReply {
  session: string;
  text: string;
  error?: string;
  model: string;
  tokens: { input: number; output: number };
  /** Browser-side backend: from receiving the question to having the answer. */
  totalMs: number;
  /** OpenCode's own clock for the assistant message. */
  opencodeMs?: number;
  /** Model calls the message caused, as Occludra saw them; null when the journal is unreachable. */
  gateway: GatewayHop[] | null;
}

/** Plain-language names for Occludra's detectors (manifests/occludra-deployment.yaml). */
export const DETECTOR_LABEL: Record<string, string> = {
  email: "email",
  "us-ssn": "número de seguro social",
  "phone-intl": "teléfono",
  iban: "cuenta bancaria (IBAN)",
  "api-key": "clave de API",
  "bearer-token": "token de acceso",
  "password-context": "contraseña",
  "password-context-ambiguous": "contraseña",
  "secret-assignment": "secreto en código",
  "person-name-context": "nombre de persona",
  "large-amount": "monto grande",
  "currency-amount": "monto de dinero",
};

export function detectorLabel(name: string): string {
  return DETECTOR_LABEL[name] ?? name;
}

/** Plain-language names for Vigil's scanners, as its messages name them. */
export function scannerLabel(name: string): string {
  if (/yara/i.test(name)) return "reglas YARA";
  if (/transformer/i.test(name)) return "clasificador";
  if (/vector/i.test(name)) return "ataques conocidos";
  return name;
}

/** "Vigil (reglas YARA, clasificador) frenó tu mensaje", or null when Vigil did not act. */
export function injectionSummary(hop: Pick<GatewayHop, "injection">): string | null {
  const v = hop.injection;
  if (!v) return null;
  if (v.error) {
    return v.direction === "request"
      ? "Vigil no pudo revisar tu mensaje y Occludra no lo mandó, por seguridad."
      : "Vigil no pudo revisar la respuesta y Occludra no te la mostró, por seguridad.";
  }
  const by = v.scanners?.length ? ` (${v.scanners.map(scannerLabel).join(", ")})` : "";
  return v.direction === "request"
    ? `Vigil detectó un posible prompt injection en el mensaje${by}: no llegó al modelo.`
    : `Vigil detectó un posible prompt injection en la respuesta del modelo${by}: no se mostró.`;
}
