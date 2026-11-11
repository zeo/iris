import { createEffect, createSignal, For, onCleanup, onMount, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  type Alert,
  type AlertKind,
  decisionAlreadySettled,
  fileName,
  visibleDecisionPrompts,
} from "../lib/alerts";
import { AppIcon } from "./AppIcon";
import { Icon } from "./Icon";

// keep in sync with MAX_CARDS in prompt.rs
const MAX_CARDS = 3;
const INFO_TIMEOUT_MS = 8_000;

type InfoCard = { id: number; title: string; body: string };
type PromptCards = { decisions: Alert[]; info: InfoCard[]; error: string | null };

function destination(remote: Extract<AlertKind, { kind: "new_app" }>["remote"]): string {
  return remote ? `${remote.addr}:${remote.port}` : "Network access";
}

export function ConnectionPrompt() {
  const [decisions, setDecisions] = createSignal<Alert[]>([]);
  const [info, setInfo] = createSignal<InfoCard[]>([]);
  const [loadError, setLoadError] = createSignal<string>();
  // the host closes when the count reaches zero, so stay quiet until the
  // first read lands
  const [loaded, setLoaded] = createSignal(false);
  // decisions answered or set aside here, hidden until the host's own list
  // catches up
  const [hidden, setHidden] = createSignal<Set<number>>(new Set());
  const [busy, setBusy] = createSignal<Set<number>>(new Set());
  const [error, setError] = createSignal<{ id: number; message: string }>();
  let refreshSequence = 0;
  let resizeQueue = Promise.resolve();

  const visibleDecisions = () =>
    visibleDecisionPrompts(decisions(), hidden(), MAX_CARDS - (loadError() ? 1 : 0));
  const visibleInfo = () => {
    const room = MAX_CARDS - visibleDecisions().length - (loadError() ? 1 : 0);
    return room > 0 ? info().slice(-room) : [];
  };
  // each stacked prompt decides independently, so track in-flight ids as a set
  // rather than a single value that would freeze the whole stack
  const isBusy = (id: number) => busy().has(id);

  const refresh = async () => {
    const sequence = ++refreshSequence;
    try {
      const next = await invoke<PromptCards>("prompt_cards");
      if (sequence !== refreshSequence) return;
      setDecisions(next.decisions);
      setHidden((current) => new Set(next.decisions.filter((alert) => current.has(alert.id)).map((alert) => alert.id)));
      setInfo(next.info);
      setLoadError(next.error ?? undefined);
    } catch (reason) {
      if (sequence === refreshSequence) setLoadError(String(reason));
    }
    setLoaded(true);
  };

  let stack: HTMLElement | undefined;
  // offset geometry forces layout and ignores the rise animation's transform,
  // so the clip matches where each card settles, even before the host shows
  const reportHitRegion = () => {
    const rects = Array.from(stack?.querySelectorAll<HTMLElement>(".connection-prompt") ?? []).map((element) => ({
      x: element.offsetLeft,
      y: element.offsetTop,
      width: element.offsetWidth,
      height: element.offsetHeight,
    }));
    void invoke("set_prompt_hit_region", { rects }).catch(() => undefined);
  };

  const timers = new Map<number, number>();
  const holdTimeout = (id: number) => {
    window.clearTimeout(timers.get(id));
    timers.delete(id);
  };
  const armTimeout = (id: number) => {
    holdTimeout(id);
    timers.set(id, window.setTimeout(() => dismissInfo(id), INFO_TIMEOUT_MS));
  };

  const hide = (id: number) => setHidden((current) => new Set(current).add(id));
  const unhide = (id: number) =>
    setHidden((current) => {
      if (!current.has(id)) return current;
      const next = new Set(current);
      next.delete(id);
      return next;
    });

  const setDecisionAside = (id: number) => {
    hide(id);
    void invoke("set_prompt_aside", { id }).catch(() => undefined);
  };

  const dismissInfo = (id: number) => {
    holdTimeout(id);
    setInfo((current) => current.filter((card) => card.id !== id));
    void invoke("dismiss_info_card", { id }).catch(() => undefined);
  };

  onMount(() => {
    // register cleanup synchronously: an onCleanup after an await runs outside
    // the owner scope and would silently fail to unregister these listeners
    let disposed = false;
    const unlisteners: Array<() => void> = [];
    const track = (pending: Promise<() => void>) => {
      void pending.then((unlisten) => (disposed ? unlisten() : unlisteners.push(unlisten)));
    };
    track(listen("connection-prompts-refresh", refresh));
    // the app asking again brings a set-aside card back; a decision settled
    // elsewhere arrives acknowledged and leaves
    track(
      listen<Alert>("engine-alert", ({ payload }) => {
        if (!payload.acknowledged) unhide(payload.id);
        void refresh();
      }),
    );
    // Escape sets the front decision aside (same as its X); it never decides,
    // so a stray key can't allow or block a connection
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      const shown = visibleDecisions();
      if (shown.length) setDecisionAside(shown[shown.length - 1].id);
    };
    window.addEventListener("keydown", onKey);
    onCleanup(() => {
      disposed = true;
      for (const unlisten of unlisteners) unlisten();
      window.removeEventListener("keydown", onKey);
      for (const timer of timers.values()) window.clearTimeout(timer);
    });
    void refresh();
  });

  createEffect(() => {
    const shownInfo = visibleInfo();
    for (const id of timers.keys()) {
      if (!shownInfo.some((card) => card.id === id)) holdTimeout(id);
    }
    for (const card of shownInfo) if (!timers.has(card.id)) armTimeout(card.id);
  });

  createEffect(() => {
    if (!loaded()) return;
    const count = visibleDecisions().length + visibleInfo().length + (loadError() ? 1 : 0);
    error();
    resizeQueue = resizeQueue
      .then(() => invoke<void>("resize_connection_prompts", { count }))
      .then(reportHitRegion)
      .catch(() => undefined);
  });

  const decide = async (alert: Alert, action: "allow" | "block") => {
    if (isBusy(alert.id)) return;
    setBusy((current) => new Set(current).add(alert.id));
    setError(undefined);
    try {
      await invoke("decide_alert", { id: alert.id, action });
      hide(alert.id);
    } catch (reason) {
      if (decisionAlreadySettled(reason)) {
        hide(alert.id);
        void refresh();
      } else {
        setError({ id: alert.id, message: String(reason) });
      }
    } finally {
      setBusy((current) => {
        const next = new Set(current);
        next.delete(alert.id);
        return next;
      });
    }
  };

  return (
    <main class="connection-prompt-stack" ref={stack}>
      <For each={visibleInfo()}>
        {(card) => (
          <section
            class="connection-prompt info"
            role="status"
            onPointerEnter={() => holdTimeout(card.id)}
            onPointerLeave={() => armTimeout(card.id)}
          >
            <header>
              <span class="prompt-mark"><Icon name="shield" /></span>
              <span><b>{card.title}</b></span>
              <button class="iconbtn" aria-label="dismiss" onClick={() => dismissInfo(card.id)}>
                <Icon name="x" />
              </button>
            </header>
            <p class="prompt-body">{card.body}</p>
          </section>
        )}
      </For>
      <Show when={loadError()}>
        {(message) => (
          <section class="connection-prompt info" role="alert">
            <header>
              <span class="prompt-mark"><Icon name="shield" /></span>
              <span><b>Could not load pending connections</b></span>
              <button class="iconbtn" aria-label="dismiss" onClick={() => setLoadError(undefined)}>
                <Icon name="x" />
              </button>
            </header>
            <p class="prompt-body prompt-error">{message()}</p>
          </section>
        )}
      </Show>
      <For each={visibleDecisions()}>
        {(alert) => {
          const application = alert.kind as Extract<AlertKind, { kind: "new_app" }>;
          return (
            <section
              class="connection-prompt"
              role="alertdialog"
              aria-modal="true"
              aria-label={`New network connection from ${fileName(application.app)}`}
            >
              <header data-tauri-drag-region>
                <span class="prompt-mark"><Icon name="shield" /></span>
                <span><b>New network connection</b><small>Choose how Iris should handle this application</small></span>
                <button class="iconbtn" aria-label="dismiss" onClick={() => setDecisionAside(alert.id)}>
                  <Icon name="x" />
                </button>
              </header>
              <div class="prompt-app">
                <AppIcon path={application.app} />
                <span><b>{fileName(application.app)}</b><small>{application.app}</small></span>
              </div>
              <div class="prompt-target">
                <span><small>Destination</small><b>{destination(application.remote)}</b></span>
                <span><small>Protocol</small><b>{application.remote?.protocol.toUpperCase() ?? "Unknown"}</b></span>
                <span><small>Direction</small><b>{application.direction ?? "outbound"}</b></span>
              </div>
              <Show when={error()?.id === alert.id}>
                <div class="prompt-error" role="alert">{error()?.message}</div>
              </Show>
              <footer>
                <button class="prompt-btn block" disabled={isBusy(alert.id)} onClick={() => decide(alert, "block")}>Block</button>
                <button class="prompt-btn allow" disabled={isBusy(alert.id)} onClick={() => decide(alert, "allow")}>
                  {isBusy(alert.id) ? "Applying…" : "Allow"}
                </button>
              </footer>
            </section>
          );
        }}
      </For>
    </main>
  );
}
