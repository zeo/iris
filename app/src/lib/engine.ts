import { createSignal } from "solid-js";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import type { Sample } from "../components/BandwidthGraph";

// shapes mirror iris-core's serialized types. AppId is a newtype over String, so
// it arrives as a plain path string.
export interface Endpoint {
  addr: string;
  port: number;
  protocol: "tcp" | "udp";
}
export interface Conn {
  remote: Endpoint;
  host: string | null;
  local_port: number;
  direction: "inbound" | "outbound";
  state: "listen" | "active" | "closing";
}
export interface ProcSample {
  pid: number;
  service: string | null;
  rate_sent: number;
  rate_recv: number;
  total: { sent: number; recv: number };
  online: boolean;
  conns: Conn[];
}
export interface AppSample {
  app: string;
  name: string | null;
  rate_sent: number;
  rate_recv: number;
  total: { sent: number; recv: number };
  connections: number;
  online: boolean;
  processes: ProcSample[];
}
export interface StatsTick {
  at_ms: number;
  total_rate_sent: number;
  total_rate_recv: number;
  apps: AppSample[];
}
interface Status {
  online: boolean;
  version: string | null;
}

// how many live samples the in-memory ring keeps for the graph and sparkline
// (300 == five minutes at one tick per second). longer ranges come from history.
const RING = 300;

const [online, setOnline] = createSignal(false);
const [version, setVersion] = createSignal<string | null>(null);
const [tick, setTick] = createSignal<StatsTick | null>(null);
const [ring, setRing] = createSignal<Sample[]>([]);

let started = false;

// register the Tauri event listeners once. safe to call from any component's
// onMount; subsequent calls are no-ops.
export function initEngine() {
  if (started) return;
  started = true;

  listen<Status>("engine-status", (e) => {
    setOnline(e.payload.online);
    setVersion(e.payload.version);
    if (!e.payload.online) {
      setTick(null);
      setRing([]);
    }
  });

  listen<StatsTick>("engine-tick", (e) => {
    const t = e.payload;
    setTick(t);
    setRing((r) => {
      const next = [...r, { sent: t.total_rate_sent, recv: t.total_rate_recv }];
      return next.length > RING ? next.slice(-RING) : next;
    });
  });

  // seed from managed state so a status event that fired before this listener
  // registered is not missed
  invoke<Status>("engine_status")
    .then((s) => {
      setOnline(s.online);
      setVersion(s.version);
    })
    .catch(() => {});
}

export const engine = {
  online,
  version,
  tick,
  ring,
  down: () => tick()?.total_rate_recv ?? 0,
  up: () => tick()?.total_rate_sent ?? 0,
  apps: () => tick()?.apps ?? [],
};
