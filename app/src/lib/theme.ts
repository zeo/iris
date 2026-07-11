import { createSignal, createEffect, onCleanup } from "solid-js";

export type ThemePref = "system" | "dark" | "light";
const KEY = "iris-theme";
const ORDER: ThemePref[] = ["system", "dark", "light"];

function resolve(pref: ThemePref): "dark" | "light" {
  if (pref === "system") {
    return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  return pref;
}

// theme preference + resolved value, persisted so the index.html pre-paint
// script picks the right background on next cold start (no flash).
export function createTheme() {
  const initial = ((): ThemePref => {
    try {
      const v = localStorage.getItem(KEY);
      if (v === "dark" || v === "light" || v === "system") return v;
    } catch {
      /* ignore */
    }
    return "system";
  })();

  const [pref, setPref] = createSignal<ThemePref>(initial);

  createEffect(() => {
    const p = pref();
    try {
      localStorage.setItem(KEY, p);
    } catch {
      /* ignore */
    }
    const mql = window.matchMedia("(prefers-color-scheme: light)");
    const apply = () => {
      document.documentElement.dataset.theme = resolve(p);
    };
    apply();
    if (p === "system") {
      mql.addEventListener("change", apply);
      onCleanup(() => mql.removeEventListener("change", apply));
    }
  });

  const cycle = () => setPref((p) => ORDER[(ORDER.indexOf(p) + 1) % ORDER.length]);
  return { pref, cycle } as const;
}
