import React from "react";
import ReactDOM from "react-dom/client";
import "./index.css";

// Branch before React mounts so no component ever violates the rules of hooks
// by conditionally calling them based on window.location.hash.
const hash = window.location.hash;
const isTaintWindow         = hash.startsWith("#/taint");
const isSearchWindow        = hash.startsWith("#/search");
const isActivityViewerWindow = hash.startsWith("#/activity-viewer");

// Lazy imports keep the main bundle small — only one branch is ever loaded.
const Root = isTaintWindow
  ? React.lazy(() => import("./TaintApp"))
  : isSearchWindow
  ? React.lazy(() => import("./SearchApp"))
  : isActivityViewerWindow
  ? React.lazy(() => import("./ActivityViewerApp"))
  : React.lazy(() => import("./App"));

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <React.Suspense fallback={null}>
      <Root />
    </React.Suspense>
  </React.StrictMode>
);
