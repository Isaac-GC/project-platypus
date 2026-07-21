import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [react()],
  // Dev server entry — the standalone harness for trying the component
  // against fixture data. Production consumers import from `src/index.ts`
  // directly via the package's exports field.
  root: "dev",
  server: {
    port: 5180,
    open: true,
  },
  resolve: {
    // Aliases let the harness `import { ViewerShell } from "@platypus/activity-viewer"`
    // without the package being npm-installed. Production consumers go
    // through the standard `exports` field in package.json.
    alias: {
      "@platypus/activity-viewer/styles.css":
        path.resolve(here, "src/styles/viewer.css"),
      "@platypus/activity-viewer":
        path.resolve(here, "src/index.ts"),
    },
  },
});
