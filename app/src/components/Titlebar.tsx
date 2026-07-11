import { getCurrentWindow } from "@tauri-apps/api/window";
import { Icon } from "./Icon";
import { Sparkline } from "./Sparkline";
import { rate } from "../lib/format";
import { engine } from "../lib/engine";
import type { ThemePref } from "../lib/theme";
import eye from "../assets/eye.png";

// custom chrome: decorations:false. brand + drag strip move the window; a compact
// always-on throughput readout sits menu-bar style before the theme key and the
// three window controls.
export function Titlebar(props: {
  theme: ThemePref;
  onCycleTheme: () => void;
  down: number;
  up: number;
}) {
  const win = () => {
    try {
      return getCurrentWindow();
    } catch {
      return null;
    }
  };
  const themeIcon = () => (props.theme === "system" ? "monitor" : props.theme === "dark" ? "moon" : "sun");

  return (
    <header class="tb">
      <div class="brand" data-tauri-drag-region>
        <img src={eye} alt="" />
        <span class="word">iris</span>
      </div>
      <div class="drag" data-tauri-drag-region />
      <div class="tb-readout" title="live throughput">
        <span class="rd">
          <span class="arrow">↓</span>
          <span class="val" classList={{ hot: props.down > 0 }}>{rate(props.down)}</span>
        </span>
        <span class="rd">
          <span class="arrow">↑</span>
          <span class="val" classList={{ hot: props.up > 0 }}>{rate(props.up)}</span>
        </span>
        <div class="spark">
          <Sparkline data={engine.ring} />
        </div>
      </div>
      <div class="tools">
        <button
          class="iconbtn"
          onClick={props.onCycleTheme}
          aria-label={`theme: ${props.theme}`}
          title={`theme: ${props.theme}`}
        >
          <Icon name={themeIcon()} />
        </button>
      </div>
      <div class="wc">
        <button class="w-min" onClick={() => win()?.minimize()} aria-label="minimize">
          <Icon name="minimize" />
        </button>
        <button class="w-max" onClick={() => win()?.toggleMaximize()} aria-label="maximize">
          <Icon name="maximize" />
        </button>
        <button class="close" onClick={() => win()?.close()} aria-label="close">
          <Icon name="close" />
        </button>
      </div>
    </header>
  );
}
