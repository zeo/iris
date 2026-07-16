import { createMemo, createSignal, For, Show } from "solid-js";
import { Key } from "@solid-primitives/keyed";
import { Icon } from "../components/Icon";
import { AppIcon } from "../components/AppIcon";
import { ConnDetails } from "../components/ConnDetails";
import { engine, type AppSample, type Conn } from "../lib/engine";
import { blockApp, isBlocked, unblockApp } from "../lib/rules";
import { persisted } from "../lib/persist";
import { bytes, rate } from "../lib/format";

function fileName(path: string): string {
  const seg = path.split(/[\\/]/).pop();
  return seg && seg.length ? seg : path;
}
function label(s: AppSample): string {
  return s.name ?? fileName(s.app);
}
function connLabel(c: Conn): string {
  return `${c.host || c.remote.addr}:${c.remote.port}`;
}

type Sort = "rate" | "down" | "up" | "conns" | "name";
type Filter = "all" | "online" | "offline";

// live per-app tree, monitor-only. app -> process -> connection. an app that
// stops connecting lingers (dimmed red) before drop.
export function Activity() {
  const [q, setQ] = createSignal("");
  // default to a stable order (by name) so rows do not jump every tick; the
  // user can sort by rate when they want the busiest at the top
  const [sort, setSort] = persisted<Sort>("activity.sort", "name");
  const [filter, setFilter] = persisted<Filter>("activity.filter", "all");
  const [openApps, setOpenApps] = createSignal<Set<string>>(new Set());
  const [openProcs, setOpenProcs] = createSignal<Set<number>>(new Set());
  const [sel, setSel] = createSignal<{ app: string; conn: Conn } | null>(null);

  const toggleApp = (app: string) =>
    setOpenApps((s) => {
      const n = new Set(s);
      n.has(app) ? n.delete(app) : n.add(app);
      return n;
    });
  const toggleProc = (pid: number) =>
    setOpenProcs((s) => {
      const n = new Set(s);
      n.has(pid) ? n.delete(pid) : n.add(pid);
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
    const so = sort();
    return [...list].sort((a, b) => {
      switch (so) {
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
                <button classList={{ on: filter() === f }} onClick={() => setFilter(f)}>{f}</button>
              )}
            </For>
          </div>
        </div>
      </div>

      <div class="tiles">
        <div class="tile"><div class="k">online apps</div><div class="v">{onlineCount()}</div></div>
        <div class="tile"><div class="k">connections</div><div class="v">{connTotal().toLocaleString()}</div></div>
        <div class="tile"><div class="k">download</div><div class="v">{rate(engine.down())}</div></div>
        <div class="tile"><div class="k">upload</div><div class="v">{rate(engine.up())}</div></div>
      </div>

      <Show
        when={rows().length > 0}
        fallback={
          <div class="empty">
            <Icon name="activity" class="glyph" size={44} />
            <h3>{engine.online() ? "No traffic yet" : "Waiting for the engine"}</h3>
            <p>
              Every app, its processes, and the endpoints they are talking to stream in here in real
              time.
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
              <Key each={rows()} by={(a) => a.app}>
                {(app) => (
                  <>
                    <tr class="app-row" classList={{ off: !app().online }} onClick={() => toggleApp(app().app)}>
                      <td>
                        <div class="app-cell">
                          <button class="chev" classList={{ open: openApps().has(app().app) }} aria-label="expand">
                            <Icon name="chevron" size={12} />
                          </button>
                          <AppIcon path={app().app} />
                          <span class="name" classList={{ offline: !app().online, blocked: isBlocked(app().app) }}>{label(app())}</span>
                          <span class="grow" />
                          <button
                            class="block-btn"
                            classList={{ on: isBlocked(app().app) }}
                            title={isBlocked(app().app) ? "unblock" : "block"}
                            onClick={(e) => {
                              e.stopPropagation();
                              isBlocked(app().app) ? unblockApp(app().app) : blockApp(app().app);
                            }}
                          >
                            <Icon name="block" size={13} />
                          </button>
                        </div>
                      </td>
                      <td class="num">{rate(app().rate_recv)}</td>
                      <td class="num">{rate(app().rate_sent)}</td>
                      <td class="num">{app().connections}</td>
                      <td class="num">{bytes(app().total.sent + app().total.recv)}</td>
                    </tr>
                    <Show when={openApps().has(app().app)}>
                      <Key each={app().processes} by={(p) => p.pid}>
                        {(proc) => (
                          <>
                            <tr class="proc-row" classList={{ off: !proc().online }} onClick={() => toggleProc(proc().pid)}>
                              <td>
                                <div class="proc-cell">
                                  <button class="chev" classList={{ open: openProcs().has(proc().pid) }} disabled={proc().conns.length === 0} aria-label="expand">
                                    <Icon name="chevron" size={12} />
                                  </button>
                                  <Icon name="cpu" class="proc-ico" size={13} />
                                  <span class="name" classList={{ offline: !proc().online }}>
                                    {proc().service ?? `Process ${proc().pid}`}
                                  </span>
                                  <Show when={proc().service}>
                                    <span class="pid">#{proc().pid}</span>
                                  </Show>
                                </div>
                              </td>
                              <td class="num">{rate(proc().rate_recv)}</td>
                              <td class="num">{rate(proc().rate_sent)}</td>
                              <td class="num">{proc().conns.length}</td>
                              <td class="num">{bytes(proc().total.sent + proc().total.recv)}</td>
                            </tr>
                            <Show when={openProcs().has(proc().pid)}>
                              <Key each={proc().conns} by={(c) => `${c.remote.addr}:${c.remote.port}:${c.local_port}`}>
                                {(c) => <ConnRow c={c()} onSelect={() => setSel({ app: app().app, conn: c() })} />}
                              </Key>
                              <Show when={proc().conns.length === 0}>
                                <tr class="conn-row"><td colSpan={5} class="conn-empty">no active connections</td></tr>
                              </Show>
                            </Show>
                          </>
                        )}
                      </Key>
                    </Show>
                  </>
                )}
              </Key>
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
  const out = () => c.direction === "outbound";
  return (
    <tr class="conn-row" classList={{ out: out(), in: !out() }} onClick={props.onSelect}>
      <td>
        <div class="conn-cell">
          <span class="dir"><Icon name={out() ? "out" : "in"} size={13} /></span>
          <span class="addr" classList={{ host: !!c.host }} title={connLabel(c)}>{connLabel(c)}</span>
        </div>
      </td>
      <td class="proto">{c.remote.protocol.toUpperCase()}</td>
      <td class="state">{c.state}</td>
      <td class="num local">:{c.local_port}</td>
      <td />
    </tr>
  );
}
