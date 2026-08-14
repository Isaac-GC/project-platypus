//! Typed AndroidManifest.xml accessors.
//!
//! The underlying [`XmlNode`] is a generic tag/attr/children tree; this
//! module turns it into typed `Activity`, `Service`, etc. structs with
//! convenience predicates like `Activity::is_launcher()`.
//!
//! Every type owns its data (clones from the source XmlNode) so callers can
//! pass it around without lifetime headaches. The trade-off is a one-time
//! copy of the manifest; on a typical app this is a few KB.

use crate::resources::Resources;
use crate::XmlNode;

/// Walk an XmlNode tree and replace every attribute value that's a resource
/// reference (`@string/foo`, `@0x7f040001`, …) with its resolved string.
/// Used by [`Manifest::with_resources`] and [`crate::layout::Layout::with_resources`].
///
/// Non-references and unresolvable refs are left unchanged.
pub(crate) fn resolve_xml_in_place(node: &mut XmlNode, resources: &Resources) {
    for (_, val) in node.attrs.iter_mut() {
        let new = resources.resolve_value(val);
        if &new != val {
            *val = new;
        }
    }
    for child in node.children.iter_mut() {
        resolve_xml_in_place(child, resources);
    }
}

// ── Manifest ────────────────────────────────────────────────────────────────

/// High-level view of a parsed AndroidManifest.xml.
#[derive(Debug, Clone)]
pub struct Manifest {
    /// The root `<manifest>` node — kept around for raw access when the
    /// typed accessors aren't enough.
    pub root: XmlNode,
}

impl Manifest {
    pub fn from_xml(root: XmlNode) -> Self {
        Self { root }
    }

    /// Build a Manifest with every `@-reference` in attribute values
    /// resolved against the supplied [`Resources`].
    ///
    /// After this, calls like `activity.label` return the resolved string
    /// (e.g. `"My App"`) instead of `"@string/app_name"`. Framework refs
    /// (`@android:string/ok`) and theme refs (`?attr/foo`) are left as-is
    /// because they can't be resolved from the app's own resources.arsc.
    ///
    /// Equivalent to:
    /// ```ignore
    /// let m = Manifest::from_xml(root);
    /// let r = Resources::new(table);
    /// let resolved = m.with_resources(&r);
    /// ```
    pub fn with_resources(self, resources: &Resources) -> Self {
        let mut root = self.root;
        resolve_xml_in_place(&mut root, resources);
        Self { root }
    }

    /// Borrowed variant — returns a new resolved manifest without
    /// consuming `self`.
    pub fn resolved(&self, resources: &Resources) -> Self {
        let mut root = self.root.clone();
        resolve_xml_in_place(&mut root, resources);
        Self { root }
    }

    /// Resolve a single attribute value of an arbitrary string in the
    /// manifest's context. Convenience for callers that don't want a
    /// fully-resolved clone — e.g. resolving just one app label on demand.
    pub fn resolve(&self, value: &str, resources: &Resources) -> String {
        resources.resolve_value(value)
    }

    /// `package` attribute on the root `<manifest>` element. The de-facto app id.
    pub fn package(&self) -> Option<&str> {
        self.root.attr("package")
    }

    /// `android:versionName` (string).
    pub fn version_name(&self) -> Option<&str> {
        self.root.attr("android:versionName")
    }

    /// `android:versionCode` (parsed as int).
    pub fn version_code(&self) -> Option<i64> {
        self.root.attr("android:versionCode")?.parse().ok()
    }

    /// `<uses-sdk android:minSdkVersion="...">`.
    pub fn min_sdk(&self) -> Option<i32> {
        self.root.find_first("uses-sdk")
            .and_then(|n| n.attr("android:minSdkVersion"))
            .and_then(|s| s.parse().ok())
    }

    /// `<uses-sdk android:targetSdkVersion="...">`.
    pub fn target_sdk(&self) -> Option<i32> {
        self.root.find_first("uses-sdk")
            .and_then(|n| n.attr("android:targetSdkVersion"))
            .and_then(|s| s.parse().ok())
    }

    /// `<uses-sdk android:maxSdkVersion="...">`.
    pub fn max_sdk(&self) -> Option<i32> {
        self.root.find_first("uses-sdk")
            .and_then(|n| n.attr("android:maxSdkVersion"))
            .and_then(|s| s.parse().ok())
    }

    /// Every `<uses-permission>` (and `<uses-permission-sdk-23>`) entry.
    pub fn uses_permissions(&self) -> Vec<UsesPermission> {
        let mut out = Vec::new();
        for tag in &["uses-permission", "uses-permission-sdk-23"] {
            for node in self.root.find_all(tag) {
                if let Some(name) = node.attr("android:name") {
                    out.push(UsesPermission {
                        name: name.to_string(),
                        max_sdk_version: node.attr("android:maxSdkVersion")
                            .and_then(|s| s.parse().ok()),
                        sdk_23_only: *tag == "uses-permission-sdk-23",
                    });
                }
            }
        }
        out
    }

    /// Just the bare permission names (with `android.permission.` stripped).
    pub fn permission_names(&self) -> Vec<String> {
        self.uses_permissions()
            .into_iter()
            .map(|p| {
                p.name
                    .strip_prefix("android.permission.")
                    .map(String::from)
                    .unwrap_or(p.name)
            })
            .collect()
    }

    /// Custom `<permission>` declarations (apps that *expose* a permission).
    pub fn permissions(&self) -> Vec<Permission> {
        self.root.find_all("permission")
            .into_iter()
            .map(Permission::from_xml)
            .collect()
    }

    /// `<uses-feature>` entries (e.g. camera, telephony).
    pub fn uses_features(&self) -> Vec<UsesFeature> {
        self.root.find_all("uses-feature")
            .into_iter()
            .map(UsesFeature::from_xml)
            .collect()
    }

    /// `<uses-library>` entries inside `<application>`.
    pub fn uses_libraries(&self) -> Vec<UsesLibrary> {
        match self.root.find_first("application") {
            Some(app) => app
                .find_all("uses-library")
                .into_iter()
                .map(UsesLibrary::from_xml)
                .collect(),
            None => Vec::new(),
        }
    }

    /// `<queries>` block (Android 11+).
    pub fn queries(&self) -> Vec<Query> {
        self.root.find_all("queries")
            .into_iter()
            .map(Query::from_xml)
            .collect()
    }

    /// The single `<application>` element, if present.
    pub fn application(&self) -> Option<Application> {
        self.root.find_first("application").map(|n| Application::from_xml(n.clone()))
    }

    /// Every `<activity>` in `<application>`.
    pub fn activities(&self) -> Vec<Activity> {
        self.app_children("activity").into_iter().map(Activity::from_xml).collect()
    }

    /// Every `<activity-alias>`.
    pub fn activity_aliases(&self) -> Vec<ActivityAlias> {
        self.app_children("activity-alias").into_iter().map(ActivityAlias::from_xml).collect()
    }

    /// Every `<service>`.
    pub fn services(&self) -> Vec<Service> {
        self.app_children("service").into_iter().map(Service::from_xml).collect()
    }

    /// Every `<receiver>`.
    pub fn receivers(&self) -> Vec<Receiver> {
        self.app_children("receiver").into_iter().map(Receiver::from_xml).collect()
    }

    /// Every `<provider>`.
    pub fn providers(&self) -> Vec<Provider> {
        self.app_children("provider").into_iter().map(Provider::from_xml).collect()
    }

    /// All four component kinds in one flat list (typed by category).
    pub fn all_components(&self) -> Vec<ComponentRef> {
        let mut out = Vec::new();
        for a in self.activities() { out.push(ComponentRef::Activity(a)); }
        for a in self.activity_aliases() { out.push(ComponentRef::ActivityAlias(a)); }
        for s in self.services() { out.push(ComponentRef::Service(s)); }
        for r in self.receivers() { out.push(ComponentRef::Receiver(r)); }
        for p in self.providers() { out.push(ComponentRef::Provider(p)); }
        out
    }

    /// Every component (any kind) that's exported (default-true if it has an
    /// intent-filter, else default-false on Android ≥ 12).
    pub fn exported_components(&self) -> Vec<ComponentRef> {
        self.all_components()
            .into_iter()
            .filter(|c| c.is_exported())
            .collect()
    }

    /// Every activity that has an intent-filter for `android.intent.action.MAIN`
    /// + `android.intent.category.LAUNCHER` (the home-screen icon).
    pub fn launcher_activities(&self) -> Vec<Activity> {
        self.activities().into_iter().filter(|a| a.is_launcher()).collect()
    }

    /// Find an activity by its FQ class name (resolves the manifest's `.Foo` /
    /// `Foo` short forms against the package).
    pub fn activity_by_name(&self, fq_name: &str) -> Option<Activity> {
        let pkg = self.package().unwrap_or("");
        self.activities()
            .into_iter()
            .find(|a| a.resolve_name(pkg) == fq_name)
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    /// Convenience: pull the children of a given tag from `<application>`.
    fn app_children(&self, tag: &str) -> Vec<XmlNode> {
        match self.root.find_first("application") {
            Some(app) => app.find_all(tag).into_iter().cloned().collect(),
            None => Vec::new(),
        }
    }
}

// ── Component types ────────────────────────────────────────────────────────

/// Tagged union for "any manifest component" — handy for code that
/// iterates over all components regardless of kind.
#[derive(Debug, Clone)]
pub enum ComponentRef {
    Activity(Activity),
    ActivityAlias(ActivityAlias),
    Service(Service),
    Receiver(Receiver),
    Provider(Provider),
}

impl ComponentRef {
    pub fn name(&self) -> &str {
        match self {
            ComponentRef::Activity(a) => &a.name,
            ComponentRef::ActivityAlias(a) => &a.name,
            ComponentRef::Service(s) => &s.name,
            ComponentRef::Receiver(r) => &r.name,
            ComponentRef::Provider(p) => &p.name,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            ComponentRef::Activity(_) => "activity",
            ComponentRef::ActivityAlias(_) => "activity-alias",
            ComponentRef::Service(_) => "service",
            ComponentRef::Receiver(_) => "receiver",
            ComponentRef::Provider(_) => "provider",
        }
    }

    pub fn intent_filters(&self) -> &[IntentFilter] {
        match self {
            ComponentRef::Activity(a) => &a.intent_filters,
            ComponentRef::ActivityAlias(a) => &a.intent_filters,
            ComponentRef::Service(s) => &s.intent_filters,
            ComponentRef::Receiver(r) => &r.intent_filters,
            ComponentRef::Provider(_) => &[],
        }
    }

    /// Heuristic: a component is exported if `android:exported="true"`, or if
    /// `android:exported` is unset *and* it has at least one intent-filter.
    /// (Android 12+ requires explicit `exported`, but historic manifests
    /// rely on this default.)
    pub fn is_exported(&self) -> bool {
        let (explicit, has_filter) = match self {
            ComponentRef::Activity(a)      => (a.exported, !a.intent_filters.is_empty()),
            ComponentRef::ActivityAlias(a) => (a.exported, !a.intent_filters.is_empty()),
            ComponentRef::Service(s)       => (s.exported, !s.intent_filters.is_empty()),
            ComponentRef::Receiver(r)      => (r.exported, !r.intent_filters.is_empty()),
            ComponentRef::Provider(p)      => (p.exported, false),
        };
        match explicit {
            Some(b) => b,
            None => has_filter,
        }
    }
}

/// `<application>` attributes plus the typed components inside it.
#[derive(Debug, Clone)]
pub struct Application {
    pub name: Option<String>,           // android:name (the Application class)
    pub label: Option<String>,
    pub icon: Option<String>,
    pub theme: Option<String>,
    pub debuggable: Option<bool>,
    pub allow_backup: Option<bool>,
    pub uses_cleartext_traffic: Option<bool>,
    pub network_security_config: Option<String>,
    pub extract_native_libs: Option<bool>,
    pub large_heap: Option<bool>,
    /// Every other `android:foo` attribute, kept verbatim for advanced queries.
    pub other_attrs: Vec<(String, String)>,
    pub meta_data: Vec<MetaData>,
    pub raw: XmlNode,
}

impl Application {
    pub fn from_xml(node: XmlNode) -> Self {
        let mut other_attrs = Vec::new();
        let mut name = None;
        let mut label = None;
        let mut icon = None;
        let mut theme = None;
        let mut debuggable = None;
        let mut allow_backup = None;
        let mut uses_cleartext_traffic = None;
        let mut network_security_config = None;
        let mut extract_native_libs = None;
        let mut large_heap = None;

        for (k, v) in &node.attrs {
            match k.as_str() {
                "android:name"                    => name = Some(v.clone()),
                "android:label"                   => label = Some(v.clone()),
                "android:icon"                    => icon = Some(v.clone()),
                "android:theme"                   => theme = Some(v.clone()),
                "android:debuggable"              => debuggable = parse_bool(v),
                "android:allowBackup"             => allow_backup = parse_bool(v),
                "android:usesCleartextTraffic"    => uses_cleartext_traffic = parse_bool(v),
                "android:networkSecurityConfig"   => network_security_config = Some(v.clone()),
                "android:extractNativeLibs"       => extract_native_libs = parse_bool(v),
                "android:largeHeap"               => large_heap = parse_bool(v),
                _ if k.starts_with("android:")    => other_attrs.push((k.clone(), v.clone())),
                _                                  => other_attrs.push((k.clone(), v.clone())),
            }
        }

        let meta_data = node.find_all("meta-data")
            .into_iter()
            .map(|n| MetaData::from_xml(n.clone()))
            .collect();

        Self {
            name, label, icon, theme, debuggable, allow_backup,
            uses_cleartext_traffic, network_security_config,
            extract_native_libs, large_heap, other_attrs, meta_data,
            raw: node,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Activity {
    pub name: String,                          // raw android:name (may be ".Foo" or full)
    pub label: Option<String>,
    pub icon: Option<String>,
    pub theme: Option<String>,
    pub exported: Option<bool>,                // None = not set (Android < 12 inferred)
    pub launch_mode: Option<String>,
    pub task_affinity: Option<String>,
    pub permission: Option<String>,
    pub config_changes: Option<String>,
    pub screen_orientation: Option<String>,
    pub parent_activity_name: Option<String>,  // for "Up" navigation
    pub intent_filters: Vec<IntentFilter>,
    pub meta_data: Vec<MetaData>,
    pub raw: XmlNode,
}

impl Activity {
    pub fn from_xml(node: XmlNode) -> Self {
        let intent_filters = node.find_all("intent-filter")
            .into_iter()
            .map(|n| IntentFilter::from_xml(n.clone()))
            .collect();
        let meta_data = node.find_all("meta-data")
            .into_iter()
            .map(|n| MetaData::from_xml(n.clone()))
            .collect();
        Self {
            name: node.attr("android:name").unwrap_or("").to_string(),
            label: node.attr("android:label").map(String::from),
            icon: node.attr("android:icon").map(String::from),
            theme: node.attr("android:theme").map(String::from),
            exported: node.attr("android:exported").and_then(parse_bool),
            launch_mode: node.attr("android:launchMode").map(String::from),
            task_affinity: node.attr("android:taskAffinity").map(String::from),
            permission: node.attr("android:permission").map(String::from),
            config_changes: node.attr("android:configChanges").map(String::from),
            screen_orientation: node.attr("android:screenOrientation").map(String::from),
            parent_activity_name: node.attr("android:parentActivityName").map(String::from),
            intent_filters,
            meta_data,
            raw: node,
        }
    }

    /// Resolve `android:name` against the package (handling leading-dot and
    /// bare-name forms). Pass the manifest's `package` attribute.
    pub fn resolve_name(&self, package: &str) -> String {
        resolve_relative_name(&self.name, package)
    }

    /// True if any intent-filter has both `android.intent.action.MAIN` and
    /// `android.intent.category.LAUNCHER` (i.e. shows on the home screen).
    pub fn is_launcher(&self) -> bool {
        self.intent_filters.iter().any(|f| {
            f.actions.iter().any(|a| a == "android.intent.action.MAIN")
                && f.categories.iter().any(|c| c == "android.intent.category.LAUNCHER")
        })
    }

    /// True if any intent-filter has `android.intent.action.MAIN` (whether or
    /// not it also has LAUNCHER). Used by some launchers and test runners.
    pub fn is_main(&self) -> bool {
        self.intent_filters.iter().any(|f| {
            f.actions.iter().any(|a| a == "android.intent.action.MAIN")
        })
    }
}

#[derive(Debug, Clone)]
pub struct ActivityAlias {
    pub name: String,
    pub target_activity: Option<String>,
    pub label: Option<String>,
    pub exported: Option<bool>,
    pub permission: Option<String>,
    pub intent_filters: Vec<IntentFilter>,
    pub meta_data: Vec<MetaData>,
    pub raw: XmlNode,
}

impl ActivityAlias {
    pub fn from_xml(node: XmlNode) -> Self {
        let intent_filters = node.find_all("intent-filter")
            .into_iter().map(|n| IntentFilter::from_xml(n.clone())).collect();
        let meta_data = node.find_all("meta-data")
            .into_iter().map(|n| MetaData::from_xml(n.clone())).collect();
        Self {
            name: node.attr("android:name").unwrap_or("").to_string(),
            target_activity: node.attr("android:targetActivity").map(String::from),
            label: node.attr("android:label").map(String::from),
            exported: node.attr("android:exported").and_then(parse_bool),
            permission: node.attr("android:permission").map(String::from),
            intent_filters,
            meta_data,
            raw: node,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Service {
    pub name: String,
    pub label: Option<String>,
    pub exported: Option<bool>,
    pub permission: Option<String>,
    pub process: Option<String>,
    pub foreground_service_type: Option<String>,
    pub isolated_process: Option<bool>,
    pub intent_filters: Vec<IntentFilter>,
    pub meta_data: Vec<MetaData>,
    pub raw: XmlNode,
}

impl Service {
    pub fn from_xml(node: XmlNode) -> Self {
        let intent_filters = node.find_all("intent-filter")
            .into_iter().map(|n| IntentFilter::from_xml(n.clone())).collect();
        let meta_data = node.find_all("meta-data")
            .into_iter().map(|n| MetaData::from_xml(n.clone())).collect();
        Self {
            name: node.attr("android:name").unwrap_or("").to_string(),
            label: node.attr("android:label").map(String::from),
            exported: node.attr("android:exported").and_then(parse_bool),
            permission: node.attr("android:permission").map(String::from),
            process: node.attr("android:process").map(String::from),
            foreground_service_type: node.attr("android:foregroundServiceType").map(String::from),
            isolated_process: node.attr("android:isolatedProcess").and_then(parse_bool),
            intent_filters,
            meta_data,
            raw: node,
        }
    }

    /// Heuristic: services with intent-filter action `AccessibilityService`
    /// are accessibility services (high-privilege channel).
    pub fn is_accessibility_service(&self) -> bool {
        self.intent_filters.iter().any(|f| {
            f.actions.iter().any(|a| a.contains("AccessibilityService"))
        })
    }
}

#[derive(Debug, Clone)]
pub struct Receiver {
    pub name: String,
    pub exported: Option<bool>,
    pub permission: Option<String>,
    pub enabled: Option<bool>,
    pub intent_filters: Vec<IntentFilter>,
    pub meta_data: Vec<MetaData>,
    pub raw: XmlNode,
}

impl Receiver {
    pub fn from_xml(node: XmlNode) -> Self {
        let intent_filters = node.find_all("intent-filter")
            .into_iter().map(|n| IntentFilter::from_xml(n.clone())).collect();
        let meta_data = node.find_all("meta-data")
            .into_iter().map(|n| MetaData::from_xml(n.clone())).collect();
        Self {
            name: node.attr("android:name").unwrap_or("").to_string(),
            exported: node.attr("android:exported").and_then(parse_bool),
            permission: node.attr("android:permission").map(String::from),
            enabled: node.attr("android:enabled").and_then(parse_bool),
            intent_filters,
            meta_data,
            raw: node,
        }
    }

    /// True if the receiver has `android.permission.BIND_DEVICE_ADMIN`
    /// (DeviceAdminReceiver pattern).
    pub fn is_device_admin(&self) -> bool {
        matches!(self.permission.as_deref(), Some("android.permission.BIND_DEVICE_ADMIN"))
    }
}

#[derive(Debug, Clone)]
pub struct Provider {
    pub name: String,
    pub authorities: Vec<String>,           // android:authorities (semicolon-split)
    pub exported: Option<bool>,
    pub grant_uri_permissions: Option<bool>,
    pub permission: Option<String>,
    pub read_permission: Option<String>,
    pub write_permission: Option<String>,
    pub multiprocess: Option<bool>,
    pub meta_data: Vec<MetaData>,
    pub raw: XmlNode,
}

impl Provider {
    pub fn from_xml(node: XmlNode) -> Self {
        let authorities = node.attr("android:authorities")
            .map(|s| s.split(';').map(str::to_string).collect())
            .unwrap_or_default();
        let meta_data = node.find_all("meta-data")
            .into_iter().map(|n| MetaData::from_xml(n.clone())).collect();
        Self {
            name: node.attr("android:name").unwrap_or("").to_string(),
            authorities,
            exported: node.attr("android:exported").and_then(parse_bool),
            grant_uri_permissions: node.attr("android:grantUriPermissions").and_then(parse_bool),
            permission: node.attr("android:permission").map(String::from),
            read_permission: node.attr("android:readPermission").map(String::from),
            write_permission: node.attr("android:writePermission").map(String::from),
            multiprocess: node.attr("android:multiprocess").and_then(parse_bool),
            meta_data,
            raw: node,
        }
    }
}

// ── Intent filter ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IntentFilter {
    pub priority: Option<i32>,
    pub auto_verify: Option<bool>,
    pub actions: Vec<String>,
    pub categories: Vec<String>,
    pub data: Vec<IntentData>,
    pub raw: XmlNode,
}

impl IntentFilter {
    pub fn from_xml(node: XmlNode) -> Self {
        let actions = node.find_all("action")
            .into_iter()
            .filter_map(|n| n.attr("android:name").map(String::from))
            .collect();
        let categories = node.find_all("category")
            .into_iter()
            .filter_map(|n| n.attr("android:name").map(String::from))
            .collect();
        let data = node.find_all("data")
            .into_iter()
            .map(|n| IntentData::from_xml(n.clone()))
            .collect();
        Self {
            priority: node.attr("android:priority").and_then(|s| s.parse().ok()),
            auto_verify: node.attr("android:autoVerify").and_then(parse_bool),
            actions,
            categories,
            data,
            raw: node,
        }
    }

    /// True if the filter declares a deep-link (has an http/https data scheme).
    pub fn is_deep_link(&self) -> bool {
        self.data.iter().any(|d| {
            d.scheme.as_deref() == Some("http") || d.scheme.as_deref() == Some("https")
        })
    }
}

#[derive(Debug, Clone)]
pub struct IntentData {
    pub scheme: Option<String>,
    pub host: Option<String>,
    pub port: Option<String>,
    pub path: Option<String>,
    pub path_pattern: Option<String>,
    pub path_prefix: Option<String>,
    pub mime_type: Option<String>,
    pub raw: XmlNode,
}

impl IntentData {
    pub fn from_xml(node: XmlNode) -> Self {
        Self {
            scheme: node.attr("android:scheme").map(String::from),
            host: node.attr("android:host").map(String::from),
            port: node.attr("android:port").map(String::from),
            path: node.attr("android:path").map(String::from),
            path_pattern: node.attr("android:pathPattern").map(String::from),
            path_prefix: node.attr("android:pathPrefix").map(String::from),
            mime_type: node.attr("android:mimeType").map(String::from),
            raw: node,
        }
    }
}

// ── Misc smaller types ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct UsesPermission {
    pub name: String,
    pub max_sdk_version: Option<i32>,
    pub sdk_23_only: bool,        // true if from <uses-permission-sdk-23>
}

#[derive(Debug, Clone)]
pub struct Permission {
    pub name: String,
    pub label: Option<String>,
    pub description: Option<String>,
    pub permission_group: Option<String>,
    pub protection_level: Option<String>,
    pub raw: XmlNode,
}

impl Permission {
    pub fn from_xml(node: &XmlNode) -> Self {
        Self {
            name: node.attr("android:name").unwrap_or("").to_string(),
            label: node.attr("android:label").map(String::from),
            description: node.attr("android:description").map(String::from),
            permission_group: node.attr("android:permissionGroup").map(String::from),
            protection_level: node.attr("android:protectionLevel").map(String::from),
            raw: node.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct UsesFeature {
    pub name: Option<String>,
    pub gl_es_version: Option<String>,
    pub required: Option<bool>,
    pub raw: XmlNode,
}

impl UsesFeature {
    pub fn from_xml(node: &XmlNode) -> Self {
        Self {
            name: node.attr("android:name").map(String::from),
            gl_es_version: node.attr("android:glEsVersion").map(String::from),
            required: node.attr("android:required").and_then(parse_bool),
            raw: node.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct UsesLibrary {
    pub name: String,
    pub required: Option<bool>,
    pub raw: XmlNode,
}

impl UsesLibrary {
    pub fn from_xml(node: &XmlNode) -> Self {
        Self {
            name: node.attr("android:name").unwrap_or("").to_string(),
            required: node.attr("android:required").and_then(parse_bool),
            raw: node.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MetaData {
    pub name: String,
    pub value: Option<String>,
    pub resource: Option<String>,        // android:resource (resource ref)
    pub raw: XmlNode,
}

impl MetaData {
    pub fn from_xml(node: XmlNode) -> Self {
        Self {
            name: node.attr("android:name").unwrap_or("").to_string(),
            value: node.attr("android:value").map(String::from),
            resource: node.attr("android:resource").map(String::from),
            raw: node,
        }
    }
}

/// Android 11+ `<queries>` block — declares which other apps this one can
/// query via `PackageManager`.
#[derive(Debug, Clone)]
pub struct Query {
    pub packages: Vec<String>,           // <package android:name="..."/>
    pub intents: Vec<IntentFilter>,      // <intent>... reused as IntentFilter
    pub providers: Vec<String>,          // <provider android:authorities="..."/>
    pub raw: XmlNode,
}

impl Query {
    pub fn from_xml(node: &XmlNode) -> Self {
        let packages = node.find_all("package")
            .into_iter()
            .filter_map(|n| n.attr("android:name").map(String::from))
            .collect();
        let intents = node.find_all("intent")
            .into_iter()
            .map(|n| IntentFilter::from_xml(n.clone()))
            .collect();
        let providers = node.find_all("provider")
            .into_iter()
            .filter_map(|n| n.attr("android:authorities").map(String::from))
            .collect();
        Self { packages, intents, providers, raw: node.clone() }
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn parse_bool(s: &str) -> Option<bool> {
    match s.to_ascii_lowercase().as_str() {
        "true"  | "1" => Some(true),
        "false" | "0" => Some(false),
        _ => None,
    }
}

/// Resolve `.Foo` → `package.Foo`, bare `Foo` → `package.Foo`, full names unchanged.
fn resolve_relative_name(name: &str, package: &str) -> String {
    if name.starts_with('.') {
        format!("{}{}", package, name)
    } else if !name.contains('.') && !package.is_empty() {
        format!("{}.{}", package, name)
    } else {
        name.to_string()
    }
}

