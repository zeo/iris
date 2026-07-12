import { createSignal } from "solid-js";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import type { Sample } from "../components/BandwidthGraph";
import { upsertProposal, type RuleProposal } from "./proposals";

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
export type AdapterKind = "ethernet" | "wifi" | "vpn" | "loopback" | "other";
export interface AdapterSample {
  kind: AdapterKind;
  rate_sent: number;
  rate_recv: number;
  total: { sent: number; recv: number };
}
export interface StatsTick {
  at_ms: number;
  total_rate_sent: number;
  total_rate_recv: number;
  apps: AppSample[];
  adapters: AdapterSample[];
}

const ADAPTER_LABELS: Record<AdapterKind, string> = {
  ethernet: "Ethernet",
  wifi: "Wi-Fi",
  vpn: "VPN",
  loopback: "Loopback",
  other: "Other",
};
export function adapterLabel(kind: AdapterKind): string {
  return ADAPTER_LABELS[kind] ?? kind;
}
interface Status {
  online: boolean;
  version: string | null;
}

// mirrors iris-core's enrichment types (externally-tagged enums over the wire)
export type EnrichTarget = { Endpoint: string } | { App: string };
export type AnnotationValue =
  | { Text: string }
  | { Badge: string }
  | { Link: { label: string; url: string } };
export interface Annotation {
  key: string;
  label: string;
  value: AnnotationValue;
  severity: "info" | "warn" | "danger";
}
interface EnrichmentEvent {
  target: EnrichTarget;
  annotations: Annotation[];
}

function endpointIp(t: EnrichTarget): string | null {
  return "Endpoint" in t ? t.Endpoint : null;
}

// how many live samples the in-memory ring keeps for the graph and sparkline
// (300 == five minutes at one tick per second). longer ranges come from history.
const RING = 300;

const [online, setOnline] = createSignal(false);
const [version, setVersion] = createSignal<string | null>(null);
const [tick, setTick] = createSignal<StatsTick | null>(null);
const [ring, setRing] = createSignal<Sample[]>([]);
// annotations resolved by the engine, keyed by endpoint ip
const [enrichment, setEnrichment] = createSignal<Map<string, Annotation[]>>(new Map());

let started = false;

function mergeEnrichment(target: EnrichTarget, annotations: Annotation[]) {
  const ip = endpointIp(target);
  if (!ip) return;
  setEnrichment((m) => {
    const next = new Map(m);
    next.set(ip, annotations);
    return next;
  });
}

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

  listen<EnrichmentEvent>("engine-enrichment", (e) => {
    mergeEnrichment(e.payload.target, e.payload.annotations);
  });

  listen<RuleProposal>("engine-proposal", (e) => upsertProposal(e.payload));

  // seed from managed state so a status event that fired before this listener
  // registered is not missed
  invoke<Status>("engine_status")
    .then((s) => {
      setOnline(s.online);
      setVersion(s.version);
    })
    .catch(() => {});
}

// fetch any cached annotations for these ips now; live pushes keep them current
export async function fetchEnrichment(ips: string[]) {
  try {
    const list = await invoke<EnrichmentEvent[]>("get_enrichment", { ips });
    for (const e of list) mergeEnrichment(e.target, e.annotations);
  } catch {
    // engine offline; the live push path fills these in once it connects
  }
}

export const engine = {
  online,
  version,
  tick,
  ring,
  enrichment,
  annotationsFor: (ip: string): Annotation[] => enrichment().get(ip) ?? [],
  down: () => tick()?.total_rate_recv ?? 0,
  up: () => tick()?.total_rate_sent ?? 0,
  apps: () => tick()?.apps ?? [],
  adapters: () => tick()?.adapters ?? [],
};
