import { createSignal, type Signal } from "solid-js";

// a signal whose value is mirrored to localStorage, so view preferences
// (filters, sort, period) survive relaunches
export function persisted<T>(key: string, initial: T): Signal<T> {
  let start = initial;
  try {
    const raw = localStorage.getItem(key);
    if (raw != null) start = JSON.parse(raw) as T;
  } catch {
    /* ignore */
  }
  const [get, set] = createSignal<T>(start);
  const persist: Signal<T>[1] = ((value) => {
    const next = set(value as never);
    try {
      localStorage.setItem(key, JSON.stringify(get()));
    } catch {
      /* ignore */
    }
    return next;
  }) as Signal<T>[1];
  return [get, persist];
}
