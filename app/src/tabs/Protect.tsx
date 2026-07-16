import { createEffect, createMemo, createSignal, For, Show } from "solid-js";
import { Key } from "@solid-primitives/keyed";
import { invoke } from "@tauri-apps/api/core";
import { revealItemInDir } from "@tauri-apps/plugin-opener";
import { AppIcon } from "../components/AppIcon";
import { Icon } from "../components/Icon";
import { forgetKnownApp, knownApps, refreshKnownApps } from "../lib/apps";
import { engine, type AppSample } from "../lib/engine";
import { bytes, rate } from "../lib/format";
import { acceptProposal, pendingProposals, refreshProposals, rejectProposal } from "../lib/proposals";
import { addRule, refreshRules, removeRule, rules, type StoredRule } from "../lib/rules";
import { fileName, pathKey } from "../lib/path";

type Direction = "inbound" | "outbound";
type Decision = "open" | "allow" | "block" | "paused";
type SortKey = "app" | "down" | "up" | "session";
type SortDirection = "asc" | "desc";

interface AppRow {
  app: string;
  name?: string;
  sample?: AppSample;
  rules: StoredRule[];
}

function decisionFor(row: AppRow, direction: Direction): Decision {
  const directional = row.rules.filter((stored) => stored.rule.direction === direction);
  if (directional.some((stored) => stored.enabled && stored.rule.action === "block")) return "block";
  if (directional.some((stored) => stored.enabled && stored.rule.action === "allow")) return "allow";
  return directional.length ? "paused" : "open";
}

function hostsFor(sample?: AppSample): string {
  if (!sample) return "no live endpoints";
  const list = sample.hosts;
  if (list.length === 0) return sample.online ? "waiting for connection" : "last seen this session";
  return list.length > 2 ? `${list.slice(0, 2).join(", ")} +${list.length - 2}` : list.join(", ");
}

export function Protect() {
  const [query, setQuery] = createSignal("");
  const [filter, setFilter] = createSignal<"all" | "active" | "ruled">("all");
  const [adding, setAdding] = createSignal(false);
  const [action, setAction] = createSignal<"block" | "allow">("block");
  const [direction, setDirection] = createSignal<Direction>("outbound");
  const [toolError, setToolError] = createSignal("");
  const [toolNote, setToolNote] = createSignal("");
  const [ioBusy, setIoBusy] = createSignal(false);
  const [changing, setChanging] = createSignal("");
  const [sort, setSort] = createSignal<SortKey>("app");
  const [sortDirection, setSortDirection] = createSignal<SortDirection>("asc");

  createEffect(() => {
    if (!engine.online()) return;
    refreshRules();
    refreshProposals();
    refreshKnownApps();
  });

  const appRows = createMemo<AppRow[]>(() => {
    const byPath = new Map<string, AppRow>();
    for (const known of knownApps()) {
      byPath.set(pathKey(known.app), {
        app: known.app,
        name: known.name ?? undefined,
        rules: [],
      });
    }
    for (const sample of engine.apps()) {
      const key = pathKey(sample.app);
      const row = byPath.get(key);
      if (sample.online || row) {
        byPath.set(key, {
          app: sample.app,
          name: sample.name ?? row?.name,
          sample,
          rules: row?.rules ?? [],
        });
      }
    }
    for (const stored of rules()) {
      const key = pathKey(stored.rule.app);
      const row = byPath.get(key) ?? { app: stored.rule.app, rules: [] };
      row.rules.push(stored);
      byPath.set(key, row);
    }

    const needle = query().trim().toLowerCase();
    const mode = filter();
    return [...byPath.values()]
      .filter((row) => mode === "all" || (mode === "active" ? row.sample?.online : row.rules.length > 0))
      .filter((row) => {
        if (!needle) return true;
        const name = row.sample?.name ?? row.name ?? fileName(row.app);
        return name.toLowerCase().includes(needle) || row.app.toLowerCase().includes(needle) || hostsFor(row.sample).toLowerCase().includes(needle);
      })
      .sort((a, b) => {
        const name = (row: AppRow) => row.sample?.name ?? row.name ?? fileName(row.app);
        const total = (row: AppRow) => (row.sample?.total.recv ?? 0) + (row.sample?.total.sent ?? 0);
        let order = 0;
        switch (sort()) {
          case "down":
            order = (a.sample?.rate_recv ?? 0) - (b.sample?.rate_recv ?? 0);
            break;
          case "up":
            order = (a.sample?.rate_sent ?? 0) - (b.sample?.rate_sent ?? 0);
            break;
          case "session":
            order = total(a) - total(b);
            break;
          default:
            order = name(a).localeCompare(name(b));
        }
        if (sortDirection() === "desc") order *= -1;
        return order || name(a).localeCompare(name(b));
      });
  });

  const chooseSort = (next: SortKey) => {
    if (sort() === next) {
      setSortDirection((current) => (current === "asc" ? "desc" : "asc"));
      return;
    }
    setSort(next);
    setSortDirection(next === "app" ? "asc" : "desc");
  };

  const candidates = createMemo(() => {
    const covered = new Set(
      rules()
        .filter((stored) => stored.rule.direction === direction())
        .map((stored) => pathKey(stored.rule.app)),
    );
    return engine.apps().filter((sample) => !covered.has(pathKey(sample.app)));
  });

  const blockedCount = () =>
    new Set(rules().filter((stored) => stored.enabled && stored.rule.action === "block").map((stored) => pathKey(stored.rule.app))).size;
  const activeCount = () => engine.apps().filter((sample) => sample.online).length;
  const connectionCount = () => engine.apps().reduce((sum, sample) => sum + sample.connections, 0);

  const chooseDecision = async (row: AppRow, direction: Direction, next: Decision) => {
    const key = `${row.app}:${direction}`;
    if (decisionFor(row, direction) === next || changing()) return;
    setChanging(key);
    setToolError("");
    try {
      for (const stored of row.rules.filter((rule) => rule.rule.direction === direction)) {
        await removeRule(stored.id);
      }
      if (next === "allow" || next === "block") await addRule(row.app, direction, next);
    } catch (error) {
      setToolError(String(error));
      await refreshRules();
    } finally {
      setChanging("");
    }
  };

  const exportRules = async () => {
    if (ioBusy()) return;
    setIoBusy(true);
    setToolError("");
    setToolNote("");
    try {
      const contents = JSON.stringify(
        rules().map((stored) => ({ ...stored.rule, enabled: stored.enabled })),
        null,
        2,
      );
      const path = await invoke<string>("save_download", { name: "iris-rules.json", contents });
      await revealItemInDir(path);
    } catch (error) {
      setToolError(String(error));
    } finally {
      setIoBusy(false);
    }
  };

  const importRules = async () => {
    if (ioBusy()) return;
    setIoBusy(true);
    setToolError("");
    setToolNote("");
    try {
      const count = await invoke<number | null>("rule_import");
      if (count === null) return;
      await refreshRules();
      setToolNote(`imported ${count} rule${count === 1 ? "" : "s"}`);
    } catch (error) {
      setToolError(String(error));
    } finally {
      setIoBusy(false);
    }
  };

  const accept = async (id: number) => {
    setToolError("");
    try {
      await acceptProposal(id);
    } catch (error) {
      setToolError(String(error));
    }
  };

  const dismiss = async (id: number) => {
    setToolError("");
    try {
      await rejectProposal(id);
    } catch (error) {
      setToolError(String(error));
    }
  };

  return (
    <section class="protect-console">
      <div class="protect-deck">
        <div class="protect-gauge">
          <span class="label">Enforcement</span>
          <div class="protect-state">
            <span class="lamp" classList={{ live: engine.online(), off: !engine.online() }} />
            <strong>{engine.online() ? "ON LINE" : "OFF LINE"}</strong>
          </div>
          <span class="protect-caption">engine {engine.version() ?? "unavailable"}</span>
        </div>
        <div class="protect-gauge">
          <span class="label">Live field</span>
          <div class="protect-readout"><b>{activeCount()}</b> apps <i>{connectionCount()} links</i></div>
          <span class="protect-caption">{rate(engine.down())} down · {rate(engine.up())} up</span>
        </div>
        <div class="protect-gauge">
          <span class="label">Rule bank</span>
          <div class="protect-readout"><b>{rules().length}</b> rules <i>{blockedCount()} blocked</i></div>
          <span class="protect-caption">inbound and outbound decisions</span>
        </div>
        <div class="protect-tools">
          <label class="field protect-search">
            <Icon name="search" />
            <input
              placeholder="search app, path, or endpoint"
              value={query()}
              onInput={(event) => setQuery(event.currentTarget.value)}
            />
          </label>
          <div class="seg" role="group" aria-label="application filter">
            <For each={["all", "active", "ruled"] as const}>
              {(mode) => <button classList={{ on: filter() === mode }} onClick={() => setFilter(mode)}>{mode}</button>}
            </For>
          </div>
        </div>
      </div>

      <div class="protect-command">
        <span class="label">Application control</span>
        <span class="protect-legend"><i class="open" /> open <i class="allow" /> allow rule <i class="block" /> blocked</span>
        <span class="grow" />
        <Show when={pendingProposals().length > 0}>
          <button class="btn proposal-count" onClick={() => setAdding(false)}>{pendingProposals().length} proposed</button>
        </Show>
        <button class="btn" onClick={() => setAdding((open) => !open)}><Icon name="plus" /> Add rule</button>
        <button class="btn icon" onClick={exportRules} disabled={ioBusy() || rules().length === 0} title="Export rules"><Icon name="download" /></button>
        <button class="btn icon" onClick={importRules} disabled={ioBusy()} title="Import rules"><Icon name="upload" /></button>
      </div>

      <Show when={toolError()}><div class="tool-err">{toolError()}</div></Show>
      <Show when={toolNote()}><div class="tool-note">{toolNote()}</div></Show>

      <Show when={pendingProposals().length > 0}>
        <div class="proposal-strip">
          <For each={pendingProposals()}>
            {(proposal) => (
              <div class="proposal-entry">
                <AppIcon path={proposal.rule.app} />
                <span><b>{fileName(proposal.rule.app)}</b><small>{proposal.source} · {proposal.reason}</small></span>
                <span class={`decision-mark ${proposal.rule.action}`}>{proposal.rule.action} {proposal.rule.direction === "outbound" ? "out" : "in"}</span>
                <button class="btn" onClick={() => accept(proposal.id)}>Accept</button>
                <button class="iconbtn" onClick={() => dismiss(proposal.id)} aria-label="dismiss proposal"><Icon name="x" /></button>
              </div>
            )}
          </For>
        </div>
      </Show>

      <Show when={adding()}>
        <div class="panel picker protect-picker">
          <div class="picker-head">
            <span class="label">new rule from a live application</span>
            <div class="picker-opts">
              <div class="seg" role="group" aria-label="action">
                <button classList={{ on: action() === "block" }} onClick={() => setAction("block")}>block</button>
                <button classList={{ on: action() === "allow" }} onClick={() => setAction("allow")}>allow</button>
              </div>
              <div class="seg" role="group" aria-label="direction">
                <button classList={{ on: direction() === "outbound" }} onClick={() => setDirection("outbound")}>out</button>
                <button classList={{ on: direction() === "inbound" }} onClick={() => setDirection("inbound")}>in</button>
              </div>
            </div>
            <button class="iconbtn" onClick={() => setAdding(false)} aria-label="close"><Icon name="x" /></button>
          </div>
          <div class="picker-list">
            <For each={candidates()} fallback={<div class="picker-empty">no uncovered live applications</div>}>
              {(sample) => (
                <button
                  class="picker-row"
                  onClick={async () => {
                    setToolError("");
                    try {
                      await addRule(sample.app, direction(), action());
                    } catch (error) {
                      setToolError(String(error));
                    }
                  }}
                >
                  <AppIcon path={sample.app} />
                  <span class="name">{sample.name ?? fileName(sample.app)}</span>
                  <span class="grow" />
                  <span class={`decision-mark ${action()}`}>{action()} {direction() === "outbound" ? "out" : "in"}</span>
                </button>
              )}
            </For>
          </div>
        </div>
      </Show>

      <Show
        when={appRows().length > 0}
        fallback={
          <div class="empty protect-empty">
            <Icon name="shield" class="glyph" size={44} />
            <h3>{engine.online() ? "No applications match" : "Waiting for the engine"}</h3>
            <p>Live applications and saved rules appear here as soon as the engine reports them.</p>
          </div>
        }
      >
        <div class="panel protect-table-wrap">
          <table class="tbl protect-table">
            <thead>
              <tr>
                <SortHeader label="Application" value="app" sort={sort()} direction={sortDirection()} choose={chooseSort} />
                <th>Inbound</th>
                <th>Outbound</th>
                <th>Remote field</th>
                <SortHeader label="↓ rate" value="down" numeric sort={sort()} direction={sortDirection()} choose={chooseSort} />
                <SortHeader label="↑ rate" value="up" numeric sort={sort()} direction={sortDirection()} choose={chooseSort} />
                <SortHeader label="session" value="session" numeric sort={sort()} direction={sortDirection()} choose={chooseSort} />
              </tr>
            </thead>
            <tbody>
              <Key each={appRows()} by={(row) => pathKey(row.app)}>
                {(row) => (
                  <tr classList={{ dormant: !row().sample?.online, blocked: decisionFor(row(), "inbound") === "block" || decisionFor(row(), "outbound") === "block" }}>
                    <td>
                      <div class="protect-app-cell">
                        <span class="app-live" classList={{ on: !!row().sample?.online }} />
                        <AppIcon path={row().app} />
                        <span class="protect-app-meta">
                          <b>{row().sample?.name ?? row().name ?? fileName(row().app)}</b>
                          <small title={row().app}>{row().app}</small>
                        </span>
                        <Show when={!row().sample?.online}>
                          <button
                            class="protect-forget"
                            aria-label={`remove ${fileName(row().app)} from Protect`}
                            title="Remove from Protect"
                            onClick={() => void forgetKnownApp(row().app)}
                          >
                            <Icon name="x" size={10} />
                          </button>
                        </Show>
                      </div>
                    </td>
                    <td><DecisionSelect row={row()} direction="inbound" changing={changing()} choose={chooseDecision} /></td>
                    <td><DecisionSelect row={row()} direction="outbound" changing={changing()} choose={chooseDecision} /></td>
                    <td><span class="remote-field" title={hostsFor(row().sample)}>{hostsFor(row().sample)}</span></td>
                    <td class="num">{rate(row().sample?.rate_recv ?? 0)}</td>
                    <td class="num">{rate(row().sample?.rate_sent ?? 0)}</td>
                    <td class="num">{bytes((row().sample?.total.recv ?? 0) + (row().sample?.total.sent ?? 0))}</td>
                  </tr>
                )}
              </Key>
            </tbody>
          </table>
        </div>
      </Show>
    </section>
  );
}

function SortHeader(props: {
  label: string;
  value: SortKey;
  numeric?: boolean;
  sort: SortKey;
  direction: SortDirection;
  choose: (sort: SortKey) => void;
}) {
  const selected = () => props.sort === props.value;
  return (
    <th classList={{ num: !!props.numeric }} aria-sort={selected() ? (props.direction === "asc" ? "ascending" : "descending") : "none"}>
      <button class="protect-sort" classList={{ on: selected() }} onClick={() => props.choose(props.value)}>
        <span>{props.label}</span>
        <span class="protect-sort-mark">{selected() ? (props.direction === "asc" ? "↑" : "↓") : "↕"}</span>
      </button>
    </th>
  );
}

function DecisionSelect(props: {
  row: AppRow;
  direction: Direction;
  changing: string;
  choose: (row: AppRow, direction: Direction, decision: Decision) => Promise<void>;
}) {
  const value = () => decisionFor(props.row, props.direction);
  const busy = () => props.changing === `${props.row.app}:${props.direction}`;
  return (
    <label
      class="decision-select"
      classList={{ busy: busy(), block: value() === "block", allow: value() === "allow", paused: value() === "paused" }}
    >
      <span class="decision-light" />
      <select
        value={value()}
        disabled={busy()}
        aria-label={`${props.direction} rule for ${fileName(props.row.app)}`}
        onChange={(event) => props.choose(props.row, props.direction, event.currentTarget.value as Decision)}
      >
        <option value="open">open</option>
        <Show when={value() === "paused"}><option value="paused" disabled>paused</option></Show>
        <option value="allow">allow</option>
        <option value="block">block</option>
      </select>
      <Icon name="chevron" size={11} />
    </label>
  );
}
