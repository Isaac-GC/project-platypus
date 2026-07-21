/**
 * Mock ViewerApi backed by static fixture JSON files. Used by the Vite
 * dev server (and optionally as a Storybook-style fixture in tests).
 *
 * Real shells supply their own implementation: the standalone viewer
 * proxies to its own Tauri commands; the Project Platypus integration
 * proxies to the existing main-app commands.
 */

import type { ViewerApi, ActivitySummary, ActivityView } from "@platypus/activity-viewer";

import sampleActivities from "./fixtures/sample-activities.json";
import sampleMain from "./fixtures/sample-main.json";
import sampleSettings from "./fixtures/sample-settings.json";

const STATIC: Record<string, unknown> = {
  "com.example.app.MainActivity": sampleMain,
  "com.example.app.SettingsActivity": sampleSettings,
};

const VIEWS: Record<string, ActivityView> = {
  // Static fixtures still ship with snake_case keys (legacy) — normalise
  // them to the camelCase IR shape on the way in. New fixtures should be
  // written camelCase from the start.
  ...Object.fromEntries(
    Object.entries(STATIC).map(([k, v]) => [k, normaliseFixture(v) as ActivityView]),
  ),

  // Compose-only and no-layout activities show the empty / diagnostic states
  "com.example.app.ComposeActivity": {
    activityName: "com.example.app.ComposeActivity",
    layoutId: null, layoutPath: null,
    outgoingNavigations: [],
    diagnostics: [{
      severity: "info",
      message:
        "Activity uses Jetpack Compose. Reconstructed via static call-graph " +
        "walk from Lcom/example/app/ComposeActivityKt;->MyApp(Composer;I)V " +
        "(depth-limited, conditional branches collapsed).",
      location: "com.example.app.ComposeActivity",
    }],
    root: {
      tag: "MyApp",
      kind: { kind: "custom", className: "MyApp" },
      source: { kind: "compose", methodRef: "Lcom/example/app/ComposeActivityKt;->MyApp(Landroidx/compose/runtime/Composer;I)V" },
      id: null,
      attrs: [{
        name: "_pap_compose_method",
        value: "Lcom/example/app/ComposeActivityKt;->MyApp(Landroidx/compose/runtime/Composer;I)V",
        origin: { kind: "static" },
      }],
      clickHandler: null, navigation: null, dynamicModifications: [], itemTemplate: null, drawables: {},
      children: [
        {
          tag: "Scaffold",
          kind: { kind: "coordinatorLayout" },
          source: { kind: "compose", methodRef: "Landroidx/compose/material3/ScaffoldKt;->Scaffold(...)V" },
          id: null, attrs: [],
          clickHandler: null, navigation: null, dynamicModifications: [], itemTemplate: null, drawables: {},
          children: [
            {
              tag: "TopAppBar",
              kind: { kind: "toolbar" },
              source: { kind: "compose", methodRef: "Landroidx/compose/material3/AppBarKt;->TopAppBar(...)V" },
              id: null,
              attrs: [{ name: "title", value: "Compose demo", origin: { kind: "static" } }],
              clickHandler: null, navigation: null, dynamicModifications: [], itemTemplate: null, drawables: {},
              children: [],
            },
            {
              tag: "Column",
              kind: { kind: "linearLayout" },
              source: { kind: "compose", methodRef: "Landroidx/compose/foundation/layout/ColumnKt;->Column(...)V" },
              id: null,
              attrs: [{ name: "android:orientation", value: "vertical", origin: { kind: "static" } }],
              clickHandler: null, navigation: null, dynamicModifications: [], itemTemplate: null, drawables: {},
              children: [
                {
                  tag: "Text",
                  kind: { kind: "text" },
                  source: { kind: "compose", methodRef: "Landroidx/compose/material3/TextKt;->Text(...)V" },
                  id: null,
                  attrs: [{ name: "android:text", value: "Hello, Compose!", origin: { kind: "static" } }],
                  clickHandler: null, navigation: null, dynamicModifications: [], itemTemplate: null, drawables: {},
                  children: [],
                },
                {
                  tag: "Button",
                  kind: { kind: "button" },
                  source: { kind: "compose", methodRef: "Landroidx/compose/material3/ButtonKt;->Button(...)V" },
                  id: null,
                  attrs: [{ name: "android:text", value: "Tap me", origin: { kind: "static" } }],
                  clickHandler: null, navigation: null, dynamicModifications: [], itemTemplate: null, drawables: {},
                  children: [],
                },
              ],
            },
          ],
        },
      ],
    },
  },
  "com.example.app.NoLayoutActivity": {
    activityName: "com.example.app.NoLayoutActivity",
    layoutId: null, layoutPath: null, root: null,
    outgoingNavigations: [],
    diagnostics: [
      {
        severity: "warning",
        message: "No setContentView/inflate call found. May be a base class " +
                 "or use a default theme window.",
        location: "com.example.app.NoLayoutActivity",
      },
    ],
  },
  "com.example.app.LoginActivity": {
    activityName: "com.example.app.LoginActivity",
    layoutId: 2131361827,
    layoutPath: "res/layout/activity_login.xml",
    diagnostics: [],
    outgoingNavigations: [
      {
        kind: "startActivity",
        target: "com.example.app.MainActivity",
      },
    ],
    root: {
      tag: "LinearLayout",
      kind: { kind: "linearLayout" },
      source: { kind: "xml", layoutPath: "res/layout/activity_login.xml" },
      id: null,
      attrs: [
        { name: "android:orientation", value: "vertical", origin: { kind: "static" } },
        { name: "android:padding",     value: "24dp",     origin: { kind: "static" } },
      ],
      clickHandler: null, navigation: null, dynamicModifications: [], itemTemplate: null, drawables: {},
      children: [
        {
          tag: "EditText",
          kind: { kind: "editText" }, id: "email",
          source: { kind: "xml", layoutPath: "res/layout/activity_login.xml" },
          attrs: [
            { name: "android:layout_width",  value: "match_parent", origin: { kind: "static" } },
            { name: "android:layout_height", value: "wrap_content", origin: { kind: "static" } },
            { name: "android:hint",          value: "Email",        origin: { kind: "static" } },
            { name: "android:inputType",     value: "textEmailAddress", origin: { kind: "static" } },
          ],
          clickHandler: null, navigation: null, dynamicModifications: [], itemTemplate: null, drawables: {},
          children: [],
        },
        {
          tag: "EditText",
          kind: { kind: "editText" }, id: "password",
          source: { kind: "xml", layoutPath: "res/layout/activity_login.xml" },
          attrs: [
            { name: "android:layout_width",  value: "match_parent",  origin: { kind: "static" } },
            { name: "android:layout_height", value: "wrap_content",  origin: { kind: "static" } },
            { name: "android:hint",          value: "Password",      origin: { kind: "static" } },
            { name: "android:inputType",     value: "textPassword",  origin: { kind: "static" } },
          ],
          clickHandler: null, navigation: null, dynamicModifications: [], itemTemplate: null, drawables: {},
          children: [],
        },
        {
          tag: "Button",
          kind: { kind: "button" }, id: "submit",
          source: { kind: "xml", layoutPath: "res/layout/activity_login.xml" },
          attrs: [
            { name: "android:layout_width",  value: "match_parent", origin: { kind: "static" } },
            { name: "android:layout_height", value: "wrap_content", origin: { kind: "static" } },
            { name: "android:layout_marginTop", value: "16dp",      origin: { kind: "static" } },
            { name: "android:text",          value: "Sign in",      origin: { kind: "static" } },
          ],
          clickHandler: {
            kind: "codeOnClickListener",
            target: "Lcom/example/app/LoginActivity$1;->onClick(Landroid/view/View;)V",
          },
          navigation: null, dynamicModifications: [], itemTemplate: null, drawables: {},
          children: [],
        },
      ],
    },
  },
};

export class MockApi implements ViewerApi {
  async appLabel(): Promise<string> {
    return "Sample App (mock data)";
  }

  async listActivities(): Promise<ActivitySummary[]> {
    // Static fixture is snake_case-keyed; reuse the same normaliser.
    return normaliseFixture(sampleActivities) as ActivitySummary[];
  }

  async rehydrateActivity(name: string): Promise<ActivityView> {
    const view = VIEWS[name];
    if (!view) {
      return {
        activityName: name,
        layoutId: null, layoutPath: null, root: null,
        outgoingNavigations: [],
        diagnostics: [{
          severity: "error",
          message: `MockApi has no fixture for ${name}`,
          location: name,
        }],
      };
    }
    // Tiny artificial delay so the loading state is visible during dev.
    await new Promise((r) => setTimeout(r, 100));
    return view;
  }

  async openActivity(name: string): Promise<void> {
    console.log("[MockApi] openActivity →", name);
  }

  async jumpToSource(methodRef: string): Promise<void> {
    console.log("[MockApi] jumpToSource →", methodRef);
    alert(`jumpToSource:\n${methodRef}\n\n(host would open this method in the code editor)`);
  }

  async openLayoutFile(path: string): Promise<void> {
    console.log("[MockApi] openLayoutFile →", path);
    alert(`openLayoutFile:\n${path}\n\n(host would open this XML in the code editor)`);
  }
}

// ── Legacy snake_case → camelCase normaliser (for the static JSON fixtures) ─

const KEY_RENAMES: Record<string, string> = {
  activity_name: "activityName",
  layout_id: "layoutId",
  layout_path: "layoutPath",
  click_handler: "clickHandler",
  dynamic_modifications: "dynamicModifications",
  is_launcher: "isLauncher",
  from_layout_path: "fromLayoutPath",
  included_layout_path: "includedLayoutPath",
  stub_layout_path: "stubLayoutPath",
  target_layout_path: "targetLayoutPath",
  method_ref: "methodRef",
  from_method: "fromMethod",
  class_name: "className",
  style_name: "styleName",
};

function normaliseFixture(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(normaliseFixture);
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      const newKey = KEY_RENAMES[k] ?? k;
      // attrs[].origin used to be a bare string ("static"/"dynamic"/"style").
      // The Rust IR encodes it as a tagged enum {kind: "static"} so we
      // upgrade old fixtures here.
      if (newKey === "origin" && typeof v === "string") {
        out[newKey] = { kind: v };
      } else {
        out[newKey] = normaliseFixture(v);
      }
    }
    // Backfill new fields the legacy snake_case fixtures predate.
    if ("activityName" in out && !("outgoingNavigations" in out)) {
      out.outgoingNavigations = [];
    }
    // Phase 10: every UnifiedView gets an itemTemplate slot. Detect a view
    // node by its required fields and backfill `null`.
    if ("kind" in out && "tag" in out && "attrs" in out
        && !("itemTemplate" in out)) {
      out.itemTemplate = null;
    }
    // Drawables map (post-13). Same view-node detection as above.
    if ("kind" in out && "tag" in out && "attrs" in out
        && !("drawables" in out)) {
      out.drawables = {};
    }
    return out;
  }
  return value;
}
