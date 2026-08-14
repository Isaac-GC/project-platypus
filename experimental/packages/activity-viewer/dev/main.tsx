/**
 * Dev harness — mounts the ViewerShell with mocked fixture data so the
 * component can be developed/tested without a Tauri shell.
 *
 * Run with `npm run dev` from the package root → opens at http://localhost:5180.
 */

import React from "react";
import { createRoot } from "react-dom/client";
import { ViewerShell } from "@platypus/activity-viewer";
import "@platypus/activity-viewer/styles.css";
import { MockApi } from "./MockApi";

const root = createRoot(document.getElementById("root")!);
root.render(
  <React.StrictMode>
    <ViewerShell api={new MockApi()} />
  </React.StrictMode>,
);
