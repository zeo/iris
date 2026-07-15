import { createEffect, onCleanup, onMount } from "solid-js";

// a sample the graph plots: sent/received bytes-per-second at a moment. the ring
// is filled by the live stream once the engine is running; until then the scope
// holds a powered-on "no signal" marker.
export interface Sample {
  sent: number;
  recv: number;
}

function css(el: HTMLElement, name: string): string {
  return getComputedStyle(el).getPropertyValue(name).trim();
}

export function BandwidthGraph(props: {
  /** ring of recent samples, newest last; empty => idle */
  data?: () => Sample[];
  /** height in px */
  height?: number;
}) {
  let canvas!: HTMLCanvasElement;

  onMount(() => {
    const ctx = canvas.getContext("2d")!;
    let raf = 0;
    let looping = false;

    const frame = () => {
      const dpr = window.devicePixelRatio || 1;
      const w = canvas.clientWidth;
      const h = canvas.clientHeight;
      if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
        canvas.width = w * dpr;
        canvas.height = h * dpr;
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);

      const line = css(canvas, "--line") || "#2c2a26";
      const steel = css(canvas, "--steel") || "#cec9bd";
      const deep = css(canvas, "--steel-deep") || "#736f65";
      const faint = css(canvas, "--faint") || "#64615a";

      // engraved grid: horizontal divisions + faint verticals
      ctx.strokeStyle = line;
      ctx.lineWidth = 1;
      const rows = 4;
      for (let i = 0; i <= rows; i++) {
        const y = Math.round((i / rows) * h) + 0.5;
        ctx.globalAlpha = i === rows ? 0.9 : 0.5;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
      }
      ctx.globalAlpha = 0.25;
      const cols = 12;
      for (let i = 1; i < cols; i++) {
        const x = Math.round((i / cols) * w) + 0.5;
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, h);
        ctx.stroke();
      }
      ctx.globalAlpha = 1;

      const samples = props.data?.() ?? [];

      if (samples.length < 2) {
        // idle: a soft baseline glow + a fixed scanline, "no signal"
        const baseY = h - 1;
        ctx.strokeStyle = deep;
        ctx.globalAlpha = 0.6;
        ctx.beginPath();
        ctx.moveTo(0, baseY);
        ctx.lineTo(w, baseY);
        ctx.stroke();
        ctx.globalAlpha = 1;

        const sweep = w * 0.62;
        const grad = ctx.createLinearGradient(sweep - 90, 0, sweep, 0);
        grad.addColorStop(0, "rgba(206,201,189,0)");
        grad.addColorStop(1, "rgba(206,201,189,0.16)");
        ctx.fillStyle = grad;
        ctx.fillRect(sweep - 90, 0, 90, h);
        ctx.strokeStyle = steel;
        ctx.globalAlpha = 0.4;
        ctx.beginPath();
        ctx.moveTo(sweep, 0);
        ctx.lineTo(sweep, h);
        ctx.stroke();
        ctx.globalAlpha = 1;

        ctx.fillStyle = faint;
        ctx.font = `9.5px "Geist Mono", ui-monospace, monospace`;
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.save();
        ctx.globalAlpha = 0.7;
        ctx.fillText("NO SIGNAL", w / 2, h / 2);
        ctx.restore();

        looping = false;
        return;
      }

      // live: scale to the peak in view, plot received (filled) + sent (line)
      const peak = Math.max(1, ...samples.map((s) => Math.max(s.sent, s.recv)));
      const n = samples.length;
      const x = (i: number) => (i / (n - 1)) * w;
      const y = (v: number) => h - (v / peak) * (h - 4) - 1;

      // received, steel area
      ctx.beginPath();
      ctx.moveTo(0, h);
      samples.forEach((s, i) => ctx.lineTo(x(i), y(s.recv)));
      ctx.lineTo(w, h);
      ctx.closePath();
      const area = ctx.createLinearGradient(0, 0, 0, h);
      area.addColorStop(0, "rgba(206,201,189,0.28)");
      area.addColorStop(1, "rgba(206,201,189,0.02)");
      ctx.fillStyle = area;
      ctx.fill();
      ctx.strokeStyle = steel;
      ctx.lineWidth = 1.4;
      ctx.beginPath();
      samples.forEach((s, i) => (i ? ctx.lineTo(x(i), y(s.recv)) : ctx.moveTo(x(i), y(s.recv))));
      ctx.stroke();

      // sent, brighter thin line
      ctx.strokeStyle = css(canvas, "--live") || "#f2ecdc";
      ctx.globalAlpha = 0.85;
      ctx.lineWidth = 1;
      ctx.beginPath();
      samples.forEach((s, i) => (i ? ctx.lineTo(x(i), y(s.sent)) : ctx.moveTo(x(i), y(s.sent))));
      ctx.stroke();
      ctx.globalAlpha = 1;

      // live view repaints on new data, not on a free-running loop
      looping = false;
    };

    const request = () => {
      if (!looping) {
        looping = true;
        raf = requestAnimationFrame(frame);
      }
    };

    // repaint only when the ring changes
    createEffect(() => {
      props.data?.();
      request();
    });
    window.addEventListener("resize", request);
    onCleanup(() => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", request);
    });
  });

  return (
    <div class="scope" style={{ height: `${props.height ?? 300}px` }}>
      <canvas ref={canvas} />
    </div>
  );
}
