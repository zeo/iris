import { createResource, createSignal, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import { Icon } from "./Icon";
import type { Conn } from "../lib/engine";

// the connection detail drawer: properties + tools for one connection, opened by
// clicking a connection row. rules are handled in Protect, so this omits them.
export function ConnDetails(props: { app: string; conn: Conn; onClose: () => void }) {
  const [rdns] = createResource(
    () => props.conn.remote.addr,
    (ip) => invoke<string | null>("reverse_dns", { ip }),
  );

  const [killed, setKilled] = createSignal(false);
  const [killErr, setKillErr] = createSignal("");
  const remote = () => `${props.conn.remote.addr}:${props.conn.remote.port}`;
  const copy = () => navigator.clipboard?.writeText(remote()).catch(() => {});
  const whois = () => openUrl(`https://who.is/whois-ip/ip-address/${props.conn.remote.addr}`);
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
        {row("Country", <span class="unresolved">Unresolved</span>)}
        {row("State", props.conn.state)}
      </div>

      <div class="tools">
        <div class="plabel">Tools</div>
        <div class="tool-row">
          <button class="btn" onClick={copy}>Copy address</button>
          <button class="btn" onClick={whois}>Whois</button>
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
