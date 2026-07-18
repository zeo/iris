import { invoke } from "@tauri-apps/api/core";

// tell the native side the webview's real device-pixel-ratio so it can size the
// window to land the CSS viewport at its intended width. webkit's content scale
// under fractional display scaling is not something the host can reliably guess,
// so we measure it here and report changes when the window crosses monitors.
export function initDisplayScale(): void {
  let reported = 0;
  const report = () => {
    const scale = window.devicePixelRatio;
    if (!Number.isFinite(scale) || scale <= 0 || Math.abs(scale - reported) < 0.005) {
      return;
    }
    reported = scale;
    void invoke("report_display_scale", { scale }).catch(() => {});
  };

  // devicePixelRatio fires no change event; a resolution media query does, and it
  // has to be re-armed against the new ratio each time it trips
  let media: MediaQueryList | null = null;
  const onChange = () => {
    report();
    arm();
  };
  const arm = () => {
    media?.removeEventListener("change", onChange);
    media = window.matchMedia(`(resolution: ${window.devicePixelRatio}dppx)`);
    media.addEventListener("change", onChange);
  };

  report();
  arm();
}
