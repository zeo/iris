import { createStore } from "solid-js/store";
import { invoke } from "@tauri-apps/api/core";

// per-app-path icon cache. the backend extracts an exe's icon once; results are
// kept here so a row re-rendering every tick never re-fetches. an empty string
// means "resolved, no icon" (fall back to the generic mark).
const [icons, setIcons] = createStore<Record<string, string>>({});
const requested = new Set<string>();

/// kick off a fetch for this path if not already done. idempotent, async.
export function requestIcon(path: string) {
  if (requested.has(path)) return;
  requested.add(path);
  invoke<string | null>("app_icon", { path })
    .then((d) => setIcons(path, d ?? ""))
    .catch(() => setIcons(path, ""));
}

/// reactive read of the resolved data URI, or undefined until known / if none
export function iconData(path: string): string | undefined {
  return icons[path] || undefined;
}
