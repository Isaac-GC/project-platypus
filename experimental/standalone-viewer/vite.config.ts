import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 5181,
    strictPort: true,
    watch: {
      ignored: ["**/src-tauri/**"],
    },
  },
  resolve: {
    // Same alias the Project Platypus integration uses — points at the
    // shared @platypus/activity-viewer source.
    alias: {
      "@platypus/activity-viewer/styles.css":
        path.resolve(here, "../packages/activity-viewer/src/styles/viewer.css"),
      "@platypus/activity-viewer":
        path.resolve(here, "../packages/activity-viewer/src/index.ts"),
    },
  },
});
