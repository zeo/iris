import { createEffect, createResource, createSignal, For, onCleanup, onMount, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import { Icon } from "./Icon";
import { engine, fetchEnrichment, type Annotation, type Conn } from "../lib/engine";

// the connection detail drawer: properties + tools for one connection, opened by
// clicking a connection row. rules are handled in Protect, so this omits them.
export function ConnDetails(props: { app: string; conn: Conn; onClose: () => void }) {
  const [rdns] = createResource(
    () => props.conn.remote.addr,
    // a failed lookup (engine offline, ipv6, command error) must not throw in
    // render and take down the whole ui; fall back to unresolved like a miss
    (ip) => invoke<string | null>("reverse_dns", { ip }).catch(() => null),
  );
  // pull any cached engine annotations for this endpoint; live pushes keep the
  // store current while the drawer is open
  createEffect(() => {
    fetchEnrichment([props.conn.remote.addr]);
  });
  onMount(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") props.onClose();
    };
    window.addEventListener("keydown", onKey);
    onCleanup(() => window.removeEventListener("keydown", onKey));
  });

  const annotations = () => engine.annotationsFor(props.conn.remote.addr);
  const annText = (a: Annotation): string => {
    if ("Text" in a.value) return a.value.Text;
    if ("Badge" in a.value) return a.value.Badge;
    return a.value.Link.label;
  };
  // plugin-supplied links are only ever opened as http(s); a plugin cannot drive
  // the system handler to file:, custom-scheme, or javascript: targets
  const openExternal = (raw: string) => {
    try {
      const url = new URL(raw);
      if (url.protocol === "http:" || url.protocol === "https:") void openUrl(url.href);
    } catch {
      /* not a usable url */
    }
  };
  const annClick = (a: Annotation) => {
    if ("Link" in a.value) openExternal(a.value.Link.url);
  };

  const [killed, setKilled] = createSignal(false);
  const [killErr, setKillErr] = createSignal("");
  const remote = () => `${props.conn.remote.addr}:${props.conn.remote.port}`;
  const copy = () => navigator.clipboard?.writeText(remote()).catch(() => {});
  const whois = () =>
    openUrl(`https://who.is/whois-ip/ip-address/${encodeURIComponent(props.conn.remote.addr)}`);
  const virustotal = () =>
    openUrl(
      props.conn.host
        ? `https://www.virustotal.com/gui/domain/${encodeURIComponent(props.conn.host)}`
        : `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(props.conn.remote.addr)}`,
    );
  const kill = async () => {
    setKillErr("");
    try {
      await invoke("kill_connection", {
        localPort: props.conn.local_port,
        remoteAddr: props.conn.remote.addr,
        remotePort: props.conn.remote.port,
      });
      setKilled(true);
    } catch (e) {
      setKillErr(String(e));
    }
  };

  const row = (k: string, v: unknown) => (
    <div class="prow">
      <span class="pk">{k}</span>
      <span class="pv">{v as string}</span>
    </div>
  );

  return (
    <aside class="details">
      <div class="details-head">
        <span class="dir">{props.conn.direction === "outbound" ? "↗" : "↘"}</span>
        <div class="titles">
          <h3>{props.conn.direction === "outbound" ? "Outgoing" : "Incoming"} connection</h3>
          <span class="sub">{props.app.split(/[\\/]/).pop()}</span>
        </div>
        <button class="iconbtn" onClick={props.onClose} aria-label="close">
          <Icon name="x" />
        </button>
      </div>

      <div class="props">
        <div class="plabel">Connection properties</div>
        {row("Protocol", props.conn.remote.protocol.toUpperCase())}
        {row("Host", props.conn.host ?? <span class="unresolved">Unknown</span>)}
        {row("Local port", `:${props.conn.local_port}`)}
        {row("Remote address", props.conn.remote.addr)}
        {row("Remote port", props.conn.remote.port)}
        {row(
          "Reverse DNS",
          <Show when={!rdns.loading} fallback={<span class="resolving">resolving…</span>}>
            {rdns() ?? <span class="unresolved">Unresolved</span>}
          </Show>,
        )}
        <For each={annotations()}>
          {(a) => (
            <div class="prow" classList={{ warn: a.severity === "warn", danger: a.severity === "danger" }}>
              <span class="pk">{a.label}</span>
              <Show
                when={"Link" in a.value}
                fallback={<span class="pv">{annText(a)}</span>}
              >
                <button class="pv linklike" onClick={() => annClick(a)}>{annText(a)}</button>
              </Show>
            </div>
          )}
        </For>
        {row("State", props.conn.state)}
      </div>

      <div class="tools">
        <div class="plabel">Tools</div>
        <div class="tool-row">
          <button class="btn" onClick={copy}>Copy address</button>
          <button class="btn" onClick={whois}>Whois</button>
          <button class="btn" onClick={virustotal}>VirusTotal</button>
          <button class="btn" data-variant="danger" onClick={kill} disabled={killed()}>
            <Icon name="power" /> {killed() ? "Killed" : "Kill connection"}
          </button>
        </div>
        <Show when={killErr()}>
          <div class="tool-err">{killErr()}</div>
        </Show>
      </div>
    </aside>
  );
}
