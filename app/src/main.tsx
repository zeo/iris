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
import "./styles.css";

const root = document.getElementById("root");
if (!root) throw new Error("root element missing");

const connectionPrompts = new URLSearchParams(location.search).has("connection-prompts");
if (connectionPrompts) {
  document.documentElement.classList.add("prompt-window");
}

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

document.getElementById("boot")?.remove();
