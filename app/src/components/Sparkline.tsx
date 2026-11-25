import { createEffect, onCleanup, onMount } from "solid-js";
import type { Sample } from "./BandwidthGraph";

function css(el: HTMLElement, name: string): string {
  return getComputedStyle(el).getPropertyValue(name).trim();
}

// the mini instrument in the always-on readout. idles on a faint powered-on
// marker and plots the recent ring once live.
export function Sparkline(props: { data?: () => Sample[]; theme?: string }) {
  let canvas!: HTMLCanvasElement;

  onMount(() => {
    const ctx = canvas.getContext("2d")!;
    let raf = 0;
    let resizePending = false;
    let cachedW = 0;
    let cachedH = 0;
    let cachedDpr = 0;
    let cachedTheme: string | undefined;
    let steel = "#9e9e9e";
    let live = "#f4f4f4";

    const readSize = () => {
      cachedW = canvas.clientWidth;
      cachedH = canvas.clientHeight;
      cachedDpr = window.devicePixelRatio || 1;
    };

    const readColors = () => {
      const theme = document.documentElement.dataset.theme;
      if (theme === cachedTheme) return;
      cachedTheme = theme;
      steel = css(canvas, "--steel-dim") || "#9e9e9e";
      live = css(canvas, "--live") || "#f4f4f4";
    };

    const draw = (samples: Sample[]) => {
      const dpr = window.devicePixelRatio || 1;
      if (cachedW <= 0 || cachedH <= 0 || dpr !== cachedDpr) {
        readSize();
      }
      if (cachedW <= 0 || cachedH <= 0) {
        scheduleResize();
        return;
      }
      const w = cachedW;
      const h = cachedH;
      // match integer canvas backing dimensions so fractional dpr does not reallocate every tick
      const pw = Math.trunc(w * cachedDpr);
      const ph = Math.trunc(h * cachedDpr);
      if (canvas.width !== pw || canvas.height !== ph) {
        canvas.width = pw;
        canvas.height = ph;
      }
      ctx.setTransform(cachedDpr, 0, 0, cachedDpr, 0, 0);
      ctx.clearRect(0, 0, w, h);

      readColors();

      const n = samples.length;
      if (n < 2) {
        const midY = h / 2 + 0.5;
        ctx.strokeStyle = steel;
        ctx.globalAlpha = 0.35;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(0, midY);
        ctx.lineTo(w, midY);
        ctx.stroke();
        ctx.fillStyle = live;
        ctx.globalAlpha = 0.9;
        ctx.beginPath();
        ctx.arc(w * 0.16, midY, 1.6, 0, Math.PI * 2);
        ctx.fill();
        ctx.globalAlpha = 1;
        return;
      }

      let peak = 1;
      for (let i = 0; i < n; i++) {
        const total = samples[i].sent + samples[i].recv;
        if (total > peak) peak = total;
      }
      const span = h - 3;
      const denom = n - 1;
      ctx.strokeStyle = live;
      ctx.lineWidth = 1.2;
      ctx.beginPath();
      for (let i = 0; i < n; i++) {
        const x = (i / denom) * w;
        const y = h - ((samples[i].sent + samples[i].recv) / peak) * span - 1;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.stroke();
    };

    const scheduleResize = () => {
      if (resizePending) return;
      resizePending = true;
      raf = requestAnimationFrame(() => {
        resizePending = false;
        readSize();
        draw(props.data?.() ?? []);
      });
    };

    // draw synchronously inside the tick batch so readout and sparkline share one frame
    createEffect(() => {
      props.theme;
      draw(props.data?.() ?? []);
    });
    window.addEventListener("resize", scheduleResize);
    onCleanup(() => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", scheduleResize);
    });
  });

  return <canvas ref={canvas} style={{ width: "100%", height: "100%", display: "block" }} />;
}
