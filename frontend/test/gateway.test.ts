import { type AddressInfo } from "node:net";
import { type Server, createServer } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { injectionSummary } from "../src/model/chat.ts";
import { href, parseRoute } from "../src/router.ts";

// A fake Occludra journal with one entry per client; chat.ts reads its env at
// import, so the module is loaded after it is listening.
const entries = [
  { id: 1, at: "2026-11-09T15:00:02Z", client: "external", redactions: {}, status: 403, durationMs: 300, requestBytes: 500, responseBytes: 90, blockedBy: "vigil:request", injection: { direction: "request", scanners: ["YARA signature(s)"] } },
  { id: 2, at: "2026-11-09T15:00:01Z", client: "ui-chat", redactions: { "password-context": 1 }, status: 200, durationMs: 900, requestBytes: 700, responseBytes: 300 },
];

function listen(server: Server): Promise<string> {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)));
}

const occludra = createServer((req, res) => {
  const q = new URL(req.url ?? "/", "http://x").searchParams;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify({ entries: entries.filter((e) => e.client === q.get("client") && e.id > Number(q.get("after") ?? 0)) }));
});

let ui: Server;
let base = "";

beforeAll(async () => {
  process.env["CHAT_URL"] = "http://127.0.0.1:1";
  process.env["OCCLUDRA_INSPECT_URL"] = await listen(occludra);
  const { handleGateway } = await import("../server/chat.ts");
  ui = createServer((req, res) => void handleGateway(req, res));
  base = await listen(ui);
});

afterAll(() => {
  for (const s of [occludra, ui]) s.close();
});

describe("GET /api/gateway", () => {
  it("merges the UI chat and external clients, oldest first", async () => {
    const res = await fetch(`${base}/api/gateway`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { enabled: boolean; model: string; entries: { client: string }[] };
    expect(body.enabled).toBe(true);
    expect(body.model).toBe("gemma-4-12b-it");
    expect(body.entries.map((e) => e.client)).toEqual(["ui-chat", "external"]);
  });

  it("only answers GET", async () => {
    expect((await fetch(`${base}/api/gateway`, { method: "POST" })).status).toBe(405);
  });
});

describe("routes", () => {
  it("has a page per functionality", () => {
    expect(parseRoute("#/chat")).toEqual({ page: "chat" });
    expect(parseRoute("#/seguridad")).toEqual({ page: "security" });
    expect(href({ page: "security" })).toBe("#/seguridad");
    expect(parseRoute("#/")).toEqual({ page: "servers" });
  });
});

describe("injectionSummary", () => {
  it("says which way and which scanners", () => {
    expect(injectionSummary({ injection: { direction: "request", scanners: ["YARA signature(s)", "transformer model"] } })).toBe(
      "Vigil detectó un posible prompt injection en el mensaje (reglas YARA, clasificador): no llegó al modelo.",
    );
    expect(injectionSummary({ injection: { direction: "response", error: "timeout" } })).toMatch(/no pudo revisar la respuesta/);
    expect(injectionSummary({})).toBeNull();
  });
});
