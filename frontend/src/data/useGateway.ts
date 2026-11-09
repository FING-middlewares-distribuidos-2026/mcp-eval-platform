// What Occludra did for the protected chat and for external OpenCode clients
// (GET /api/gateway, server/chat.ts). Polled while the page is open; the
// journal keeps metadata only and the latest 100 entries per client.
import { useEffect, useState } from "react";
import type { GatewayHop } from "../model/chat.ts";

export interface GatewayLog {
  state: "loading" | "ready" | "off" | "error";
  model: string;
  entries: GatewayHop[];
  error?: string;
}

const EVERY_MS = 5000;

export function useGateway(enabled: boolean): GatewayLog {
  const [log, setLog] = useState<GatewayLog>({ state: "loading", model: "", entries: [] });
  useEffect(() => {
    if (!enabled) return;
    let stop = false;
    const poll = async () => {
      try {
        const res = await fetch("/api/gateway", { cache: "no-store" });
        const body = (await res.json()) as { enabled?: boolean; model?: string; entries?: GatewayHop[]; error?: string };
        if (stop) return;
        if (!res.ok) setLog((l) => ({ ...l, state: "error", error: body.error ?? `HTTP ${res.status}` }));
        else setLog({ state: body.enabled ? "ready" : "off", model: body.model ?? "", entries: body.entries ?? [] });
      } catch (err) {
        if (!stop) setLog((l) => ({ ...l, state: "error", error: err instanceof Error ? err.message : String(err) }));
      }
    };
    void poll();
    const timer = setInterval(() => void poll(), EVERY_MS);
    return () => {
      stop = true;
      clearInterval(timer);
    };
  }, [enabled]);
  return log;
}
