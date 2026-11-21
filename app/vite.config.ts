import { defineConfig } from "vite";
import solidPlugin from "vite-plugin-solid";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const manifest = JSON.parse(
  readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "package.json"), "utf-8"),
) as { version: string };

export default defineConfig({
  plugins: [solidPlugin()],
  clearScreen: false,
  // 1423 leaves 1420 (capscr) and 1421 (orchard) free to run side by side
  server: { port: 1423, strictPort: true },
  define: {
    __APP_VERSION__: JSON.stringify(manifest.version),
  },
  build: {
    target: "esnext",
    minify: "oxc",
    sourcemap: false,
    outDir: "dist",
  },
});
