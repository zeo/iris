import { render } from "solid-js/web";
import { ErrorBoundary } from "solid-js";
import "@fontsource/hanken-grotesk/400.css";
import "@fontsource/hanken-grotesk/500.css";
import "@fontsource/hanken-grotesk/600.css";
import "@fontsource/geist-mono/400.css";
import "@fontsource/geist-mono/500.css";
import "@fontsource/newsreader/400-italic.css";
import { App } from "./App";
import { ConnectionPrompt } from "./components/ConnectionPrompt";
import { initDisplayScale } from "./lib/display";
import "./styles.css";

const root = document.getElementById("root");
if (!root) throw new Error("root element missing");

const connectionPrompts = new URLSearchParams(location.search).has("connection-prompts");
if (connectionPrompts) {
  document.documentElement.classList.add("prompt-window");
}

// the webview's own menu (reload, inspect) has no place in the app; text fields keep theirs for paste
window.addEventListener("contextmenu", (event) => {
  if (!(event.target instanceof HTMLInputElement || event.target instanceof HTMLTextAreaElement)) event.preventDefault();
});

render(
  () => (
    <ErrorBoundary
      fallback={(err, reset) => (
        <div class="crash">
          <h1>something broke</h1>
          <pre>{String(err)}</pre>
          <button class="btn" onClick={reset}>
            reload
          </button>
        </div>
      )}
    >
      {connectionPrompts ? <ConnectionPrompt /> : <App />}
    </ErrorBoundary>
  ),
  root,
);

initDisplayScale();

document.getElementById("boot")?.remove();
