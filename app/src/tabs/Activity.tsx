import { createMemo, createSignal, For, Show } from "solid-js";
import { Key } from "@solid-primitives/keyed";
import { Icon } from "../components/Icon";
import { AppIcon } from "../components/AppIcon";
import { ConnDetails } from "../components/ConnDetails";
import { engine, type AppSample, type Conn } from "../lib/engine";
import { blockApp, caps, downloadLimitsSupported, isBlocked, setCap, unblockApp } from "../lib/rules";
import { formatGb, GB, quota, setQuota, throttleRate, type QuotaPeriod } from "../lib/quota";
import { persisted } from "../lib/persist";
import { bytes, rate } from "../lib/format";
import { fileName, pathKey } from "../lib/path";
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
  const [pendingRules, setPendingRules] = createSignal<Set<string>>(new Set());
  const [ruleError, setRuleError] = createSignal("");

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
  const toggleBlock = async (sample: AppSample) => {
    if (pendingRules().has(sample.app)) return;
    const blocked = isBlocked(sample.app);
    setPendingRules((paths) => new Set(paths).add(sample.app));
    setRuleError("");
    try {
      await (blocked ? unblockApp(sample.app) : blockApp(sample.app));
    } catch (error) {
      setRuleError(
        `Could not ${blocked ? "unblock" : "block"} ${label(sample)}: ${String(error)}`,
      );
    } finally {
      setPendingRules((paths) => {
        const next = new Set(paths);
        next.delete(sample.app);
        return next;
      });
    }
  };

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
    <th class={cls} classList={{ sorted: sort() === key }} aria-sort={sort() === key ? "descending" : "none"}>
      <button class="col-sort" onClick={() => setSort(key)}>
        {text}
        <span class="sort">▾</span>
      </button>
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
            <input aria-label="Filter apps" placeholder="filter apps…" value={q()} onInput={(e) => setQ(e.currentTarget.value)} />
          </label>
          <div class="seg" role="group" aria-label="status">
            <For each={["all", "online", "offline"] as Filter[]}>
              {(f) => (
                <button classList={{ on: filter() === f }} aria-pressed={filter() === f} onClick={() => setFilter(f)}>{f}</button>
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

      <Show when={ruleError()}>
        <div class="tool-err" role="alert">{ruleError()}</div>
      </Show>

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
                <th class="num">↓ limit</th>
                <th class="num">↑ limit</th>
                <th class="num">quota</th>
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
                            aria-label={`${isBlocked(app().app) ? "Unblock" : "Block"} ${label(app())}`}
                            aria-busy={pendingRules().has(app().app)}
                            disabled={pendingRules().has(app().app)}
                            onClick={(e) => {
                              e.stopPropagation();
                              void toggleBlock(app());
                            }}
                          >
                            <Icon name="block" size={13} />
                          </button>
                        </div>
                      </td>
                      <td class="num">{rate(app().rate_recv)}</td>
                      <td class="num">{rate(app().rate_sent)}</td>
                      <LimitCell app={app().app} name={label(app())} dir="down" onError={setRuleError} />
                      <LimitCell app={app().app} name={label(app())} dir="up" onError={setRuleError} />
                      <QuotaCell app={app().app} name={label(app())} onError={setRuleError} />
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
                              <td colSpan={3} />
                              <td class="num">{proc().conns.length}</td>
                              <td class="num">{bytes(proc().total.sent + proc().total.recv)}</td>
                            </tr>
                            <Show when={openProcs().has(proc().pid)}>
                              <Key each={proc().conns} by={(c) => `${c.remote.protocol}:${c.remote.addr}:${c.remote.port}:${c.local_port}`}>
                                {(c) => <ConnRow c={c()} onSelect={() => setSel({ app: app().app, conn: c() })} />}
                              </Key>
                              <Show when={proc().conns.length === 0}>
                                <tr class="conn-row"><td colSpan={8} class="conn-empty">no active connections</td></tr>
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
  const c = () => props.c;
  const out = () => c().direction === "outbound";
  return (
    <tr
      class="conn-row"
      classList={{ out: out(), in: !out() }}
      role="button"
      tabindex={0}
      aria-label={`Inspect connection ${connLabel(c())}`}
      onClick={props.onSelect}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          props.onSelect();
        }
      }}
    >
      <td>
        <div class="conn-cell">
          <span class="dir"><Icon name={out() ? "out" : "in"} size={13} /></span>
          <span class="addr" classList={{ host: !!c().host }} title={connLabel(c())}>{connLabel(c())}</span>
          <span class="proto">{c().remote.protocol}</span>
          <span class="state">{c().state}</span>
        </div>
      </td>
      <td class="num">{rate(c().rate_recv)}</td>
      <td class="num">{rate(c().rate_sent)}</td>
      <td colSpan={3} />
      <td class="num local">:{c().local_port}</td>
      <td />
    </tr>
  );
}

// a table cell that shows its value as a button until clicked, then a field
// that saves on enter and backs out on escape or a click elsewhere
function useInlineEdit() {
  const [editing, setEditing] = createSignal(false);
  const leaveOnFocusOut = (event: FocusEvent) => {
    const next = event.relatedTarget as Node | null;
    if (!next || !(event.currentTarget as Node).contains(next)) setEditing(false);
  };
  const keys = (save: () => void) => (event: KeyboardEvent) => {
    if (event.key === "Enter") {
      event.preventDefault();
      save();
    } else if (event.key === "Escape") setEditing(false);
  };
  return { editing, setEditing, leaveOnFocusOut, keys };
}

function LimitCell(props: { app: string; name: string; dir: "down" | "up"; onError: (message: string) => void }) {
  if (props.dir === "down" && !downloadLimitsSupported) {
    return <td class="num" title="Download limits are only available on Windows">n/a</td>;
  }
  const edit = useInlineEdit();
  let input!: HTMLInputElement;
  const cap = () => caps().find((c) => pathKey(c.app) === pathKey(props.app));
  const value = () => (props.dir === "down" ? cap()?.down_bytes_per_sec : cap()?.up_bytes_per_sec) ?? null;
  const word = () => (props.dir === "down" ? "download" : "upload");
  const save = async () => {
    const text = input.value.trim();
    const kb = text === "" ? 0 : Number(text);
    if (!Number.isFinite(kb) || kb < 0) {
      props.onError("Enter a speed in KB/s, or clear the field to lift the limit.");
      return;
    }
    edit.setEditing(false);
    const next = kb > 0 ? Math.round(kb * 1024) : null;
    if (next === value()) return;
    const current = cap();
    props.onError("");
    try {
      await setCap(
        current?.app ?? props.app,
        props.dir === "up" ? next : (current?.up_bytes_per_sec ?? null),
        props.dir === "down" ? next : (current?.down_bytes_per_sec ?? null),
      );
    } catch (error) {
      props.onError(String(error));
    }
  };
  return (
    <td class="num inline-cell" onClick={(event) => event.stopPropagation()}>
      <Show
        when={edit.editing()}
        fallback={
          <button
            class="inline-btn"
            classList={{ set: value() !== null }}
            aria-label={value() === null ? `Limit the ${word()} speed of ${props.name}` : `Change the ${word()} limit for ${props.name}`}
            onClick={() => edit.setEditing(true)}
          >
            {value() === null ? "+" : `${bytes(value()!)}/s`}
          </button>
        }
      >
        <span class="num-field inline-edit" onFocusOut={edit.leaveOnFocusOut}>
          <input
            ref={(el) => {
              input = el;
              queueMicrotask(() => {
                el.focus();
                el.select();
              });
            }}
            inputmode="decimal"
            aria-label={`${props.name} ${word()} limit in KB/s, empty to lift`}
            value={value() === null ? "" : String(Math.round(value()! / 1024))}
            onKeyDown={edit.keys(() => void save())}
          />
          <span class="unit">KB/s</span>
        </span>
      </Show>
    </td>
  );
}

const PERIODS: QuotaPeriod[] = ["day", "week", "month"];

function QuotaCell(props: { app: string; name: string; onError: (message: string) => void }) {
  const edit = useInlineEdit();
  let input!: HTMLInputElement;
  let rateInput: HTMLInputElement | undefined;
  const current = () => quota.forApp(props.app);
  const slowedTo = () => {
    const q = current();
    return q ? throttleRate(q.limit) : null;
  };
  const [period, setPeriod] = createSignal<QuotaPeriod>("day");
  const [slow, setSlow] = createSignal(false);
  const used = () => {
    const q = current();
    return q ? q.used / q.limit.bytes : 0;
  };
  const open = () => {
    setPeriod(current()?.limit.period ?? "day");
    setSlow(slowedTo() !== null);
    edit.setEditing(true);
  };
  const save = async () => {
    const text = input.value.trim();
    const gb = text === "" ? 0 : Number(text);
    if (!Number.isFinite(gb) || gb < 0) {
      props.onError("Enter a quota in GB, or clear the field to remove it.");
      return;
    }
    const kb = Number(rateInput?.value.trim() || 0);
    if (gb > 0 && slow() && !(Number.isFinite(kb) && kb > 0)) {
      props.onError("Enter the speed in KB/s to slow the app to once its quota is spent.");
      return;
    }
    edit.setEditing(false);
    const q = current();
    const action = slow() ? { throttle: { bytes_per_sec: Math.round(kb * 1024) } } : ("block" as const);
    // monthly app quotas roll over with the data plan
    const limit =
      gb > 0
        ? { period: period(), bytes: Math.round(gb * GB), reset_day: quota.plan()?.limit.reset_day ?? 1, action }
        : null;
    if (!limit && !q) return;
    if (
      limit &&
      q &&
      limit.bytes === q.limit.bytes &&
      limit.period === q.limit.period &&
      throttleRate(limit) === throttleRate(q.limit)
    )
      return;
    props.onError("");
    try {
      await setQuota(q?.app ?? props.app, limit);
    } catch (error) {
      props.onError(String(error));
    }
  };
  return (
    <td class="num inline-cell" onClick={(event) => event.stopPropagation()}>
      <Show
        when={edit.editing()}
        fallback={
          <button
            class="inline-btn"
            classList={{ set: !!current(), warn: used() >= 0.8, over: used() >= 1 }}
            title={
              current()
                ? `${formatGb(current()!.used)} used this ${current()!.limit.period}` +
                  (slowedTo() === null ? "" : `, then slowed to ${bytes(slowedTo()!)}/s`)
                : undefined
            }
            aria-label={current() ? `Change the data quota for ${props.name}` : `Set a data quota for ${props.name}`}
            onClick={open}
          >
            {current() ? `${formatGb(current()!.limit.bytes)}/${current()!.limit.period}` : "+"}
          </button>
        }
      >
        <span class="num-field inline-edit" onFocusOut={edit.leaveOnFocusOut}>
          <input
            ref={(el) => {
              input = el;
              queueMicrotask(() => {
                el.focus();
                el.select();
              });
            }}
            inputmode="decimal"
            aria-label={`${props.name} data quota in GB, empty to remove`}
            value={current() ? String(current()!.limit.bytes / GB) : ""}
            onKeyDown={edit.keys(() => void save())}
          />
          <span class="unit">GB</span>
          <button
            class="period-btn"
            aria-label={`quota period, per ${period()}`}
            onClick={() => setPeriod(PERIODS[(PERIODS.indexOf(period()) + 1) % PERIODS.length])}
            onKeyDown={edit.keys(() => void save())}
          >
            /{period()}
          </button>
          <button
            class="period-btn"
            aria-label={`once the quota is spent, ${slow() ? "slow" : "block"} ${props.name}`}
            title={slow() && !downloadLimitsSupported ? "Linux slows only uploads" : undefined}
            onClick={() => setSlow(!slow())}
            onKeyDown={edit.keys(() => void save())}
          >
            {slow() ? "slow" : "block"}
          </button>
          <Show when={slow()}>
            <input
              ref={(el) => (rateInput = el)}
              inputmode="decimal"
              aria-label={`${props.name} speed once its quota is spent, in KB/s`}
              value={slowedTo() === null ? "" : String(Math.round(slowedTo()! / 1024))}
              onKeyDown={edit.keys(() => void save())}
            />
            <span class="unit">KB/s</span>
          </Show>
        </span>
      </Show>
    </td>
  );
}
