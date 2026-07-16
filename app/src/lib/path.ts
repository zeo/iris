// path helpers shared across the tabs. one source of truth so the basename and
// the platform-correct comparison key don't drift between copies.

// the last path segment (the exe name), or the whole path if it has no separator
export function fileName(path: string): string {
  const segment = path.split(/[\\/]/).pop();
  return segment && segment.length ? segment : path;
}

// a stable key for comparing app paths: Windows paths are case-insensitive, so
// fold them; everything else is compared verbatim
export function pathKey(path: string): string {
  return navigator.userAgent.includes("Windows") ? path.toLowerCase() : path;
}
