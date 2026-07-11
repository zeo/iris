import { createMemo, createSignal, For, Show } from "solid-js";
import { Icon } from "../components/Icon";
import { AppIcon } from "../components/AppIcon";
import { ConnDetails } from "../components/ConnDetails";
import { engine, type AppSample, type Conn } from "../lib/engine";
import { bytes, rate } from "../lib/format";

function fileName(path: string): string {
  const seg = path.split(/[\\/]/).pop();
  return seg && seg.length ? seg : path;
}
function label(s: AppSample): string {
  return s.name ?? fileName(s.app);
}

type Sort = "rate" | "down" | "up" | "conns" | "name";
type Filter = "all" | "online" | "offline";

// live per-app / per-connection table (NetLimiter "Activity"), monitor-only. rows
// expand to reveal the app's connections; an app that stops connecting lingers
// (name dimmed red) before the engine drops it.
export function Activity() {
  const [q, setQ] = createSignal("");
  const [sort, setSort] = createSignal<Sort>("rate");
  const [filter, setFilter] = createSignal<Filter>("all");
  const [open, setOpen] = createSignal<Set<string>>(new Set());
  const [sel, setSel] = createSignal<{ app: string; conn: Conn } | null>(null);

  const toggle = (app: string) =>
    setOpen((s) => {
      const n = new Set(s);
      n.has(app) ? n.delete(app) : n.add(app);
      return n;
    });

  const rows = createMemo(() => {
    const needle = q().trim().toLowerCase();
    const f = filter();
    let list = engine.apps();
    if (f === "online") list = list.filter((s) => s.online);
    else if (f === "offline") list = list.filter((s) => !s.online);
    if (needle)
      list = list.filter(
        (s) => label(s).toLowerCase().includes(needle) || s.app.toLowerCase().includes(needle),
      );
    const s = sort();
    return [...list].sort((a, b) => {
      switch (s) {
        case "down": return b.rate_recv - a.rate_recv;
        case "up": return b.rate_sent - a.rate_sent;
        case "conns": return b.connections - a.connections;
        case "name": return label(a).localeCompare(label(b));
        default: return b.rate_recv + b.rate_sent - (a.rate_recv + a.rate_sent);
      }
    });
  });

  const onlineCount = () => engine.apps().filter((s) => s.online).length;
  const connTotal = () => engine.apps().reduce((n, s) => n + s.connections, 0);
  const th = (key: Sort, cls: string, text: string) => (
    <th class={cls} classList={{ sorted: sort() === key }} onClick={() => setSort(key)}>
      {text}
      <span class="sort">▾</span>
    </th>
  );

  return (
    <section>
      <div class="head">
        <div class="titles">
          <h2>Activity</h2>
          <span class="sub">live per-app traffic</span>
        </div>
        <div class="actions">
          <label class="field">
            <Icon name="search" />
            <input placeholder="filter apps…" value={q()} onInput={(e) => setQ(e.currentTarget.value)} />
          </label>
          <div class="seg" role="group" aria-label="status">
            <For each={["all", "online", "offline"] as Filter[]}>
              {(f) => (
                <button classList={{ on: filter() === f }} onClick={() => setFilter(f)}>
                  {f}
                </button>
              )}
            </For>
          </div>
        </div>
      </div>

      <div class="tiles">
        <div class="tile">
          <div class="k">online apps</div>
          <div class="v">{onlineCount()}</div>
        </div>
        <div class="tile">
          <div class="k">connections</div>
          <div class="v">{connTotal()}</div>
        </div>
        <div class="tile">
          <div class="k">download</div>
          <div class="v">{rate(engine.down())}</div>
        </div>
        <div class="tile">
          <div class="k">upload</div>
          <div class="v">{rate(engine.up())}</div>
        </div>
      </div>

      <Show
        when={rows().length > 0}
        fallback={
          <div class="empty">
            <Icon name="activity" class="glyph" size={44} />
            <h3>{engine.online() ? "No traffic yet" : "Waiting for the engine"}</h3>
            <p>
              Up and down rates, connection counts, and the remote endpoints each app is talking to
              will stream in here in real time.
            </p>
          </div>
        }
      >
        <div class="panel table-wrap">
          <table class="tbl activity">
            <thead>
              <tr>
                {th("name", "", "Application")}
                {th("down", "num", "↓ rate")}
                {th("up", "num", "↑ rate")}
                {th("conns", "num", "conns")}
                <th class="num">session</th>
              </tr>
            </thead>
            <tbody>
              <For each={rows()}>
                {(s) => (
                  <>
                    <tr class="app-row" classList={{ off: !s.online }} onClick={() => toggle(s.app)}>
                      <td>
                        <div class="app-cell">
                          <button
                            class="chev"
                            classList={{ open: open().has(s.app) }}
                            aria-label="expand"
                            disabled={s.conns.length === 0}
                          >
                            <Icon name="chevron" size={12} />
                          </button>
                          <AppIcon path={s.app} />
                          <span class="name" classList={{ offline: !s.online }}>{label(s)}</span>
                        </div>
                      </td>
                      <td class="num">{rate(s.rate_recv)}</td>
                      <td class="num">{rate(s.rate_sent)}</td>
                      <td class="num">{s.connections}</td>
                      <td class="num">{bytes(s.total.sent + s.total.recv)}</td>
                    </tr>
                    <Show when={open().has(s.app)}>
                      <For each={s.conns}>
                        {(c) => <ConnRow c={c} onSelect={() => setSel({ app: s.app, conn: c })} />}
                      </For>
                      <Show when={s.conns.length === 0}>
                        <tr class="conn-row">
                          <td colSpan={5} class="conn-empty">no active connections</td>
                        </tr>
                      </Show>
                    </Show>
                  </>
                )}
              </For>
            </tbody>
          </table>
        </div>
      </Show>

      <Show when={sel()} keyed>
        {(s) => <ConnDetails app={s.app} conn={s.conn} onClose={() => setSel(null)} />}
      </Show>
    </section>
  );
}

function ConnRow(props: { c: Conn; onSelect: () => void }) {
  const c = props.c;
  return (
    <tr class="conn-row" onClick={props.onSelect}>
      <td>
        <div class="conn-cell">
          <span class="dir">{c.direction === "outbound" ? "↗" : "↘"}</span>
          <span class="addr">{c.remote.addr}:{c.remote.port}</span>
        </div>
      </td>
      <td class="proto">{c.remote.protocol.toUpperCase()}</td>
      <td class="state">{c.state}</td>
      <td class="num local">:{c.local_port}</td>
      <td />
    </tr>
  );
}
