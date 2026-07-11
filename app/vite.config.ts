import { defineConfig } from "vite";
import solidPlugin from "vite-plugin-solid";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const tauriConf = JSON.parse(
  readFileSync(
    resolve(dirname(fileURLToPath(import.meta.url)), "src-tauri", "tauri.conf.json"),
    "utf-8",
  ),
) as { version: string };

export default defineConfig({
  plugins: [solidPlugin()],
  clearScreen: false,
  // 1423 leaves 1420 (capscr) and 1421 (orchard) free to run side by side
  server: { port: 1423, strictPort: true },
  envPrefix: ["VITE_", "TAURI_"],
  define: {
    __APP_VERSION__: JSON.stringify(tauriConf.version),
  },
  build: {
    target: "esnext",
    minify: "esbuild",
    sourcemap: false,
    outDir: "dist",
  },
});
