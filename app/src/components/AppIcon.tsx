import { createEffect, Show } from "solid-js";
import { Icon } from "./Icon";
import { iconData, requestIcon } from "../lib/icons";

// the app's real exe icon, falling back to a generic mark until (or unless) it
// resolves. sizing comes from the enclosing .app-ico box.
export function AppIcon(props: { path: string; size?: number }) {
  // request out of the render body so the ipc call isn't a render side effect
  createEffect(() => requestIcon(props.path));
  return (
    <span class="app-ico">
      <Show when={iconData(props.path)} fallback={<Icon name="globe" size={props.size ?? 11} />}>
        {(src) => <img src={src()} alt="" />}
      </Show>
    </span>
  );
}
