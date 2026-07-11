import { createEffect, onCleanup, onMount } from "solid-js";
import type { Sample } from "./BandwidthGraph";

function css(el: HTMLElement, name: string): string {
  return getComputedStyle(el).getPropertyValue(name).trim();
}

// the mini instrument in the always-on readout. idles with a faint travelling
// pulse so the panel reads as powered-on; plots the recent ring once live.
export function Sparkline(props: { data?: () => Sample[] }) {
  let canvas!: HTMLCanvasElement;

  onMount(() => {
    const ctx = canvas.getContext("2d")!;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let t0 = 0;
    let raf = 0;
    // true while a frame is queued; the idle branch keeps it queued to animate,
    // the live branch clears it so we only repaint when a new sample arrives
    let looping = false;

    const frame = (ts: number) => {
      if (!t0) t0 = ts;
      const t = (ts - t0) / 1000;
      const dpr = window.devicePixelRatio || 1;
      const w = canvas.clientWidth;
      const h = canvas.clientHeight;
      if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
        canvas.width = w * dpr;
        canvas.height = h * dpr;
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);

      const steel = css(canvas, "--steel-dim") || "#9e9e9e";
      const live = css(canvas, "--live") || "#f4f4f4";
      const samples = props.data?.() ?? [];

      if (samples.length < 2) {
        const midY = h / 2 + 0.5;
        ctx.strokeStyle = steel;
        ctx.globalAlpha = 0.35;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(0, midY);
        ctx.lineTo(w, midY);
        ctx.stroke();
        ctx.globalAlpha = 1;
        if (!reduce) {
          const x = ((t * 0.4) % 1) * w;
          ctx.fillStyle = live;
          ctx.globalAlpha = 0.9;
          ctx.beginPath();
          ctx.arc(x, midY, 1.6, 0, Math.PI * 2);
          ctx.fill();
          ctx.globalAlpha = 1;
          raf = requestAnimationFrame(frame);
          return;
        }
        looping = false;
        return;
      }

      const peak = Math.max(1, ...samples.map((s) => s.sent + s.recv));
      const n = samples.length;
      ctx.strokeStyle = live;
      ctx.lineWidth = 1.2;
      ctx.beginPath();
      samples.forEach((s, i) => {
        const x = (i / (n - 1)) * w;
        const y = h - ((s.sent + s.recv) / peak) * (h - 3) - 1;
        i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
      });
      ctx.stroke();
      looping = false;
    };

    const request = () => {
      if (!looping) {
        looping = true;
        raf = requestAnimationFrame(frame);
      }
    };

    // repaint when the ring changes; the frame loop sustains itself only while
    // idle, so a live always-on monitor is not burning a full-rate rAF loop
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

  return <canvas ref={canvas} style={{ width: "100%", height: "100%", display: "block" }} />;
}
