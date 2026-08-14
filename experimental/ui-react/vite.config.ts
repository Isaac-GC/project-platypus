import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig(async () => ({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    watch: {
      ignored: ["**/src-tauri/**"],
    },
  },
  resolve: {
    // Always resolve a SINGLE copy of React, even though we bundle the
    // `@platypus/activity-viewer` package from source and it carries its own
    // react in node_modules. Without this, `vite build` can pull in two React
    // copies (one per node_modules) → runtime "Invalid hook call". Dedupe to
    // the app's own react/react-dom.
    dedupe: ["react", "react-dom"],
    // Alias `@platypus/activity-viewer` to its source — avoids needing
    // an npm-workspaces setup for what's effectively a sibling package.
    // Production consumers (the standalone shell) can use the same alias
    // or wire in proper workspaces; either works.
    alias: {
      "@platypus/activity-viewer/styles.css":
        path.resolve(here, "../packages/activity-viewer/src/styles/viewer.css"),
      "@platypus/activity-viewer":
        path.resolve(here, "../packages/activity-viewer/src/index.ts"),
    },
  },
}));
