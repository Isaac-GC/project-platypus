#!/usr/bin/env python3
"""
privacy_audit.py — Android APK data-collection analyser
Built on the platypus native library.

Usage:
    python3 tools/privacy_audit.py app.apk
    python3 tools/privacy_audit.py app.xapk  --output report.md --detail chain
    python3 tools/privacy_audit.py splits/   --tiers custom_tiers.json --depth 8
    python3 tools/privacy_audit.py app.apk   --trace "Lcom/example/Analytics;->track"
    python3 tools/privacy_audit.py app.apk   --no-confirm   # skip entrypoint check

Supports: .apk  .xapk  .apkm  .apks  directories of splits

Custom tier JSON format (--tiers):
    [
      { "name": "Critical", "emoji": "🔴",
        "permissions": ["READ_SMS", "READ_CALL_LOG", ...] },
      { "name": "High",     "emoji": "🟠",
        "permissions": ["ACCESS_FINE_LOCATION", ...] }
    ]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import zipfile
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    import platypus
except ImportError:
    sys.exit(
        "ERROR: platypus native module not found.\n"
        "       Build it with: cd rust && maturin develop --features python\n"
        "       then add the project root to PYTHONPATH."
    )


# ─── Default danger tier configuration ───────────────────────────────────────

DEFAULT_TIERS: list[dict] = [
    {
        "name": "Critical",
        "emoji": "🔴",
        "description": "Personal communications, identity, and biometrics",
        "permissions": [
            "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "RECEIVE_MMS",
            "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS",
            "READ_CONTACTS", "WRITE_CONTACTS",
            "RECORD_AUDIO",
            "CAMERA",
            "READ_PHONE_STATE", "READ_PHONE_NUMBERS",
            "USE_BIOMETRIC", "USE_FINGERPRINT",
            "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "READ_MEDIA_AUDIO",
        ],
    },
    {
        "name": "High",
        "emoji": "🟠",
        "description": "Precise location, accounts, and calendar",
        "permissions": [
            "ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
            "GET_ACCOUNTS", "MANAGE_ACCOUNTS",
            "READ_CALENDAR", "WRITE_CALENDAR",
            "BODY_SENSORS", "BODY_SENSORS_BACKGROUND",
            "ACTIVITY_RECOGNITION",
        ],
    },
    {
        "name": "Medium",
        "emoji": "🟡",
        "description": "Storage, Bluetooth, and coarse location",
        "permissions": [
            "ACCESS_COARSE_LOCATION",
            "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE",
            "BLUETOOTH", "BLUETOOTH_ADMIN",
            "BLUETOOTH_SCAN", "BLUETOOTH_CONNECT", "BLUETOOTH_ADVERTISE",
            "NEARBY_WIFI_DEVICES", "UWB_RANGING",
        ],
    },
    {
        "name": "Low",
        "emoji": "🔵",
        "description": "Network and system state",
        "permissions": [
            "INTERNET",
            "ACCESS_WIFI_STATE", "CHANGE_WIFI_STATE",
            "ACCESS_NETWORK_STATE", "CHANGE_NETWORK_STATE",
            "NFC",
            "RECEIVE_BOOT_COMPLETED",
            "FOREGROUND_SERVICE",
            "REQUEST_INSTALL_PACKAGES",
            "POST_NOTIFICATIONS",
            "VIBRATE",
        ],
    },
]


# ─── Sensitive API catalogue ──────────────────────────────────────────────────

@dataclass
class ApiTarget:
    class_ref:   str   # Dalvik, e.g. "Landroid/telephony/TelephonyManager;"
    method:      str   # bare name, e.g. "getDeviceId"
    permission:  str   # Android permission (or special token: REFLECTION, NONE, CONTENT_RESOLVER)
    description: str   # human-readable what this does
    note:        str = ""  # extra context shown in output


# Sensitive API targets — split into main catalogue and reflection catalogue
_API: list[ApiTarget] = [
    # ── SMS ──────────────────────────────────────────────────────────────────
    ApiTarget("Landroid/telephony/SmsManager;",   "sendTextMessage",         "SEND_SMS",         "Sends SMS message"),
    ApiTarget("Landroid/telephony/SmsManager;",   "sendMultipartTextMessage","SEND_SMS",         "Sends multi-part SMS"),
    ApiTarget("Landroid/telephony/SmsManager;",   "sendDataMessage",         "SEND_SMS",         "Sends data SMS"),
    ApiTarget("Landroid/telephony/SmsManager;",   "getDefault",              "READ_SMS",         "Acquires SMS manager handle"),

    # ── Phone state / device identifiers ─────────────────────────────────────
    ApiTarget("Landroid/telephony/TelephonyManager;","getDeviceId",          "READ_PHONE_STATE", "Reads IMEI/MEID"),
    ApiTarget("Landroid/telephony/TelephonyManager;","getImei",              "READ_PHONE_STATE", "Reads IMEI (API 26+)"),
    ApiTarget("Landroid/telephony/TelephonyManager;","getMeid",              "READ_PHONE_STATE", "Reads MEID"),
    ApiTarget("Landroid/telephony/TelephonyManager;","getSubscriberId",      "READ_PHONE_STATE", "Reads IMSI (SIM identifier)"),
    ApiTarget("Landroid/telephony/TelephonyManager;","getSimSerialNumber",   "READ_PHONE_STATE", "Reads SIM serial number"),
    ApiTarget("Landroid/telephony/TelephonyManager;","getLine1Number",       "READ_PHONE_NUMBERS","Reads phone number"),
    ApiTarget("Landroid/telephony/TelephonyManager;","getVoiceMailNumber",   "READ_PHONE_STATE", "Reads voicemail number"),
    ApiTarget("Landroid/telephony/TelephonyManager;","getCellLocation",      "ACCESS_FINE_LOCATION","Reads cell-tower location"),
    ApiTarget("Landroid/telephony/TelephonyManager;","getAllCellInfo",        "ACCESS_FINE_LOCATION","Reads all cell-tower info"),

    # ── Audio / microphone ────────────────────────────────────────────────────
    ApiTarget("Landroid/media/MediaRecorder;",    "prepare",                 "RECORD_AUDIO",     "Prepares audio recorder"),
    ApiTarget("Landroid/media/MediaRecorder;",    "start",                   "RECORD_AUDIO",     "Starts audio recording"),
    ApiTarget("Landroid/media/AudioRecord;",      "startRecording",          "RECORD_AUDIO",     "Starts raw audio capture"),
    ApiTarget("Landroid/media/AudioRecord;",      "read",                    "RECORD_AUDIO",     "Reads captured audio data"),

    # ── Camera ────────────────────────────────────────────────────────────────
    ApiTarget("Landroid/hardware/Camera;",                           "open",            "CAMERA","Opens camera (legacy)"),
    ApiTarget("Landroid/hardware/camera2/CameraManager;",            "openCamera",      "CAMERA","Opens camera (Camera2 API)"),
    ApiTarget("Landroidx/camera/core/CameraX;",                      "bindToLifecycle", "CAMERA","CameraX lifecycle binding"),
    ApiTarget("Landroidx/camera/lifecycle/ProcessCameraProvider;",   "bindToLifecycle", "CAMERA","CameraX provider binding"),

    # ── Location ──────────────────────────────────────────────────────────────
    ApiTarget("Landroid/location/LocationManager;","getLastKnownLocation",   "ACCESS_FINE_LOCATION","Reads last GPS fix"),
    ApiTarget("Landroid/location/LocationManager;","requestLocationUpdates", "ACCESS_FINE_LOCATION","Subscribes to location updates"),
    ApiTarget("Landroid/location/LocationManager;","requestSingleUpdate",    "ACCESS_FINE_LOCATION","Requests single location fix"),
    ApiTarget("Lcom/google/android/gms/location/FusedLocationProviderClient;","getLastLocation",       "ACCESS_FINE_LOCATION","Fused location – last known"),
    ApiTarget("Lcom/google/android/gms/location/FusedLocationProviderClient;","requestLocationUpdates","ACCESS_FINE_LOCATION","Fused location – continuous"),

    # ── Accounts ──────────────────────────────────────────────────────────────
    ApiTarget("Landroid/accounts/AccountManager;","getAccounts",             "GET_ACCOUNTS",     "Lists all device accounts"),
    ApiTarget("Landroid/accounts/AccountManager;","getAccountsByType",       "GET_ACCOUNTS",     "Lists accounts by type"),
    ApiTarget("Landroid/accounts/AccountManager;","getAccountsAndVisibilityForPackage","GET_ACCOUNTS","Lists accounts with visibility"),

    # ── Clipboard (no permission needed) ─────────────────────────────────────
    ApiTarget("Landroid/content/ClipboardManager;","getPrimaryClip",         "NONE",
              "Reads clipboard content",
              note="⚠️ No Android permission required — access is silent"),
    ApiTarget("Landroid/content/ClipboardManager;","getPrimaryClipDescription","NONE",
              "Reads clipboard metadata",
              note="⚠️ No Android permission required"),

    # ── WiFi ─────────────────────────────────────────────────────────────────
    ApiTarget("Landroid/net/wifi/WifiManager;",   "getConnectionInfo",       "ACCESS_WIFI_STATE","Reads WiFi SSID/BSSID"),
    ApiTarget("Landroid/net/wifi/WifiManager;",   "getScanResults",          "ACCESS_WIFI_STATE","Reads nearby WiFi networks"),
    ApiTarget("Landroid/net/wifi/WifiManager;",   "startScan",               "ACCESS_WIFI_STATE","Triggers WiFi scan"),

    # ── Bluetooth ────────────────────────────────────────────────────────────
    ApiTarget("Landroid/bluetooth/BluetoothAdapter;","startDiscovery",       "BLUETOOTH_SCAN",   "Discovers nearby BT devices"),
    ApiTarget("Landroid/bluetooth/BluetoothAdapter;","getAddress",           "BLUETOOTH_CONNECT","Reads local BT MAC address"),
    ApiTarget("Landroid/bluetooth/BluetoothAdapter;","getBondedDevices",     "BLUETOOTH_CONNECT","Lists paired BT devices"),

    # ── Content resolver (URI-based access — contacts, SMS, call log, etc.) ──
    ApiTarget("Landroid/content/ContentResolver;","query",                   "CONTENT_RESOLVER",
              "Content provider query",
              note="URI determines what data is accessed"),
    ApiTarget("Landroid/content/ContentResolver;","insert",                  "CONTENT_RESOLVER",
              "Content provider insert"),
    ApiTarget("Landroid/content/ContentResolver;","update",                  "CONTENT_RESOLVER",
              "Content provider update"),
    ApiTarget("Landroid/content/ContentResolver;","delete",                  "CONTENT_RESOLVER",
              "Content provider delete"),

    # ── Biometrics ───────────────────────────────────────────────────────────
    ApiTarget("Landroid/hardware/biometrics/BiometricPrompt;","authenticate","USE_BIOMETRIC",    "Biometric authentication prompt"),
    ApiTarget("Landroidx/biometric/BiometricPrompt;",         "authenticate","USE_BIOMETRIC",    "Biometric authentication (compat)"),

    # ── Sensors ──────────────────────────────────────────────────────────────
    ApiTarget("Landroid/hardware/SensorManager;","registerListener",         "BODY_SENSORS",     "Registers sensor listener"),

    # ── Shell execution (no permission, bypasses Android model) ──────────────
    ApiTarget("Ljava/lang/Runtime;",              "exec",                    "NONE",
              "Executes shell command",
              note="⚠️ Can access device data outside the Android permission model"),
    ApiTarget("Ljava/lang/ProcessBuilder;",       "start",                   "NONE",
              "Starts subprocess",
              note="⚠️ Can execute arbitrary commands"),

    # ── Network / exfiltration ────────────────────────────────────────────────
    ApiTarget("Ljava/net/URL;",                   "openConnection",          "INTERNET",         "Opens network connection"),
    ApiTarget("Ljava/net/HttpURLConnection;",     "getInputStream",          "INTERNET",         "Reads HTTP response body"),
    ApiTarget("Ljava/net/HttpURLConnection;",     "connect",                 "INTERNET",         "Establishes HTTP connection"),
    ApiTarget("Lokhttp3/OkHttpClient;",           "newCall",                 "INTERNET",         "OkHttp network call"),
    ApiTarget("Lretrofit2/Retrofit;",             "create",                  "INTERNET",         "Retrofit HTTP client creation"),
    ApiTarget("Lcom/android/volley/RequestQueue;","add",                     "INTERNET",         "Volley network request"),
]

# Reflection targets — kept separate so they surface in a dedicated section
_REFLECTION: list[ApiTarget] = [
    ApiTarget("Ljava/lang/Class;",              "forName",           "REFLECTION","Dynamic class loading by name"),
    ApiTarget("Ljava/lang/Class;",              "getDeclaredMethod", "REFLECTION","Reflects on declared method"),
    ApiTarget("Ljava/lang/Class;",              "getMethod",         "REFLECTION","Reflects on public method"),
    ApiTarget("Ljava/lang/Class;",              "getDeclaredField",  "REFLECTION","Reflects on declared field"),
    ApiTarget("Ljava/lang/reflect/Method;",     "invoke",            "REFLECTION","Invokes reflected method"),
    ApiTarget("Ljava/lang/ClassLoader;",        "loadClass",         "REFLECTION","Loads class via ClassLoader"),
    ApiTarget("Ldalvik/system/DexClassLoader;", "loadClass",         "REFLECTION","Loads class from DEX at runtime",
              note="Often used to load additional code from files or network"),
    ApiTarget("Ldalvik/system/PathClassLoader;","loadClass",         "REFLECTION","Loads class from app path"),
]

# content:// URI prefix → (android permission, human description)
_URI_MAP: dict[str, tuple[str, str]] = {
    "content://sms":                       ("READ_SMS",          "SMS messages"),
    "content://mms":                       ("READ_SMS",          "MMS messages"),
    "content://mms-sms":                   ("READ_SMS",          "MMS/SMS messages"),
    "content://call_log":                  ("READ_CALL_LOG",     "Call log"),
    "content://contacts":                  ("READ_CONTACTS",     "Contacts"),
    "content://com.android.contacts":      ("READ_CONTACTS",     "Contacts"),
    "content://calendar":                  ("READ_CALENDAR",     "Calendar events"),
    "content://com.android.calendar":      ("READ_CALENDAR",     "Calendar events"),
    "content://com.android.voicemail":     ("READ_VOICEMAIL",    "Voicemail"),
    "content://media":                     ("READ_EXTERNAL_STORAGE","Media files"),
    "content://downloads":                 ("READ_EXTERNAL_STORAGE","Downloads"),
    "content://telephony/carriers":        ("READ_PHONE_STATE",  "Carrier / APN config"),
    "content://user_dictionary":           ("READ_USER_DICTIONARY","User dictionary"),
    "content://browser":                   ("READ_HISTORY_BOOKMARKS","Browser history"),
    "content://com.android.browser":       ("READ_HISTORY_BOOKMARKS","Browser history"),
    "content://settings/secure":           ("NONE",              "Secure settings (e.g. Android ID)"),
    "content://settings/system":           ("NONE",              "System settings"),
}

# Android component → lifecycle entrypoint methods
_LIFECYCLE: dict[str, list[str]] = {
    "activity": [
        "onCreate", "onStart", "onResume", "onPause", "onStop", "onDestroy",
        "onCreateOptionsMenu", "onOptionsItemSelected", "onContextItemSelected",
        "onActivityResult", "onNewIntent", "onRestoreInstanceState",
        "onRequestPermissionsResult", "onHandleIntent",
    ],
    "service": [
        "onCreate", "onStartCommand", "onBind", "onUnbind",
        "onRebind", "onDestroy", "onHandleIntent", "onTaskRemoved",
    ],
    "receiver": ["onReceive"],
    "provider": ["onCreate", "query", "insert", "update", "delete", "getType"],
}


# ─── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class Entrypoint:
    component_type: str   # "activity" | "service" | "receiver" | "provider"
    class_name: str        # dot-notation fully-qualified
    dex_class: str         # "Lcom/example/Foo;"
    method: str            # lifecycle method name
    exported: bool = True


@dataclass
class Finding:
    api: ApiTarget
    effective_permission: str   # may differ from api.permission (ContentResolver → READ_SMS etc.)
    caller_class: str           # Dalvik "Lcom/example/Foo;"
    caller_method: str
    call_site_line: Optional[int]
    invoke_str: str
    confirmed: bool
    entrypoint: Optional[Entrypoint]
    chain: list[str]            # call chain from sensitive_api → entrypoint
    snippet: str = ""
    uri_hint: Optional[str] = None


@dataclass
class ReflectionFinding:
    caller_class: str
    caller_method: str
    invoke_str: str
    line: Optional[int]
    class_hint: Optional[str] = None   # resolved class name string constant
    method_hint: Optional[str] = None  # resolved method name string constant


# ─── APK loading ──────────────────────────────────────────────────────────────

def load_target(path: str):
    """
    Load an APK/XAPK/APKM/APKS/directory.
    Returns (apk_or_set, package_name, version_name, apk_label).
    """
    p = Path(path)
    suffix = p.suffix.lower()

    if suffix in (".xapk", ".apkm", ".apks"):
        _info(f"Detected {suffix.upper()} — extracting inner APKs…")
        tmp = tempfile.mkdtemp(prefix="platypus_audit_")
        _extract_multi_apk_zip(path, tmp)
        apk = platypus.ApkSet.from_dir(tmp)
        return apk, apk.package_name or "", apk.version_name or "", ""

    if p.is_dir():
        apk = platypus.ApkSet.from_dir(str(p))
        return apk, apk.package_name or "", apk.version_name or "", ""

    try:
        apk = platypus.Apk(path)
        label = ""
        try:
            label = apk.label or ""
        except Exception:
            pass
        return apk, apk.package_name or "", apk.version_name or "", label
    except Exception as e:
        sys.exit(f"ERROR: Could not load APK: {e}")


def _extract_multi_apk_zip(zip_path: str, dest_dir: str) -> None:
    """Extract .apk files from a XAPK/APKM/APKS ZIP into dest_dir (flat)."""
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            apk_members = [m for m in zf.infolist()
                           if m.filename.lower().endswith(".apk")]
            if not apk_members:
                sys.exit(f"ERROR: No .apk files found inside {zip_path}")
            for member in apk_members:
                target = os.path.join(dest_dir, os.path.basename(member.filename))
                with zf.open(member) as src, open(target, "wb") as dst:
                    dst.write(src.read())
    except zipfile.BadZipFile as e:
        sys.exit(f"ERROR: {zip_path} is not a valid ZIP: {e}")


def get_dex_files(apk) -> list:
    try:
        dexes = apk.dex_files()
        if not dexes:
            sys.exit("ERROR: No DEX files found in the APK.")
        return dexes
    except Exception as e:
        sys.exit(f"ERROR: Could not read DEX files: {e}")


# ─── Manifest / permission parsing ────────────────────────────────────────────

def get_manifest(apk):
    try:
        return apk.manifest_resolved()
    except Exception:
        try:
            return apk.manifest()
        except Exception as e:
            sys.exit(f"ERROR: Could not parse AndroidManifest.xml: {e}")


def extract_permissions(manifest) -> list[str]:
    """Return bare permission names (strip 'android.permission.' prefix)."""
    perms: list[str] = []
    for node in manifest.find_all("uses-permission"):
        name = node.attr("android:name") or node.attr("name") or ""
        bare = (name
                .replace("android.permission.", "")
                .replace("com.android.voicemail.permission.", ""))
        if bare:
            perms.append(bare)
    return list(dict.fromkeys(perms))  # deduplicate preserving order


def extract_entrypoints(manifest, pkg: str) -> list[Entrypoint]:
    """Extract all Android component entrypoints from the manifest."""
    eps: list[Entrypoint] = []
    app_node = manifest.find_first("application")
    if not app_node:
        return eps

    def resolve_class(name: Optional[str]) -> tuple[str, str]:
        if not name:
            return "", ""
        if name.startswith("."):
            name = pkg + name
        elif "." not in name and pkg:
            name = f"{pkg}.{name}"
        dex = "L" + name.replace(".", "/") + ";"
        return name, dex

    def is_exported(node) -> bool:
        v = (node.attr("android:exported") or "").lower()
        return v != "false"

    for tag, ctype in [("activity", "activity"), ("activity-alias", "activity"),
                       ("service", "service"), ("receiver", "receiver"),
                       ("provider", "provider")]:
        for comp in app_node.find_all(tag):
            raw = (comp.attr("android:name")
                   or comp.attr("android:targetActivity")
                   or "")
            cls, dex_cls = resolve_class(raw)
            if not cls:
                continue
            exp = is_exported(comp)
            for m in _LIFECYCLE.get(ctype, []):
                eps.append(Entrypoint(ctype, cls, dex_cls, m, exp))

    return eps


# ─── Tier helpers ─────────────────────────────────────────────────────────────

def load_tiers(path: Optional[str]) -> list[dict]:
    if not path:
        return DEFAULT_TIERS
    try:
        with open(path) as f:
            data = json.load(f)
        if not isinstance(data, list):
            sys.exit("ERROR: Tier file must be a JSON array.")
        return data
    except (OSError, json.JSONDecodeError) as e:
        sys.exit(f"ERROR: Could not load tier file: {e}")


def tier_for(perm: str, tiers: list[dict]) -> tuple[int, str, str]:
    """Return (index, name, emoji). Higher index = lower priority."""
    for i, t in enumerate(tiers):
        if perm in t.get("permissions", []):
            return i, t["name"], t.get("emoji", "⚪")
    return len(tiers), "Uncategorised", "⚪"


# ─── Find callers (thin wrapper) ──────────────────────────────────────────────

def find_callers(dex_files: list, target: str) -> list:
    """Call find_calls(target) across all DEX files, deduplicating by invoke_str."""
    seen: set[str] = set()
    results = []
    for dex in dex_files:
        try:
            for site in dex.find_calls(target):
                key = f"{site.caller_class}:{site.caller_method}:{site.invoke_str}"
                if key not in seen:
                    seen.add(key)
                    results.append(site)
        except Exception:
            pass
    return results


# ─── Reverse-BFS call graph ────────────────────────────────────────────────────

def reverse_bfs(
    dex_files: list,
    start: str,
    entrypoints: list[Entrypoint],
    max_depth: int,
) -> tuple[bool, Optional[Entrypoint], list[str]]:
    """
    Walk UP the call graph from `start` looking for an entrypoint.
    Returns (confirmed, entrypoint_or_None, chain).
    Chain goes from start → ... → entrypoint_method.
    """
    ep_index: dict[tuple[str, str], Entrypoint] = {
        (ep.dex_class, ep.method): ep for ep in entrypoints
    }

    # BFS queue: (current_method_ref, path_so_far)
    queue: deque[tuple[str, list[str]]] = deque()
    queue.append((start, [start]))
    visited: set[str] = {start}

    while queue:
        current, path = queue.popleft()
        for site in find_callers(dex_files, current):
            caller_ref = f"{site.caller_class}->{site.caller_method}"
            new_path = path + [caller_ref]

            # Is this an entrypoint?
            ep = ep_index.get((site.caller_class, site.caller_method))
            if ep:
                return True, ep, new_path

            if caller_ref not in visited and len(new_path) <= max_depth:
                visited.add(caller_ref)
                queue.append((caller_ref, new_path))

    return False, None, []


# ─── Snippet extraction ────────────────────────────────────────────────────────

def extract_snippet(dex_files: list, class_name: str, method_name: str) -> str:
    """
    Disassemble class_name and return the Smali body of method_name (≤ 50 lines).
    class_name is in Dalvik format "Lcom/example/Foo;".
    """
    for dex in dex_files:
        try:
            smali = dex.disassemble_class(class_name)
            if not smali:
                continue
            lines = smali.splitlines()
            # Locate .method declaration
            start = next(
                (i for i, l in enumerate(lines)
                 if ".method" in l and method_name in l),
                -1,
            )
            if start == -1:
                continue
            # Locate .end method
            end = len(lines)
            for i in range(start + 1, len(lines)):
                if lines[i].strip() == ".end method":
                    end = i + 1
                    break
            body = lines[start:end]
            if len(body) > 50:
                body = body[:50] + ["    ; … (truncated)"]
            return "\n".join(body)
        except Exception:
            continue
    return ""


# ─── URI / ContentResolver helpers ────────────────────────────────────────────

def resolve_content_uri(static_args: list) -> Optional[str]:
    """Extract a content:// URI from a call site's static_args if present."""
    for _, val in static_args:
        if val and isinstance(val, str) and val.startswith("content://"):
            return val
    return None


def permission_for_uri(uri: str) -> tuple[str, str]:
    """Return (permission, description) for a content:// URI."""
    for prefix, pair in _URI_MAP.items():
        if uri.startswith(prefix):
            return pair
    return "CONTENT_RESOLVER", "Content provider access"


# ─── Core analysis ────────────────────────────────────────────────────────────

def analyse(
    dex_files: list,
    entrypoints: list[Entrypoint],
    extra_targets: list[str],
    max_depth: int,
    detail: str,
    skip_confirm: bool,
    enable_reflection: bool,
) -> tuple[list[Finding], list[ReflectionFinding]]:

    findings: list[Finding] = []
    reflection_findings: list[ReflectionFinding] = []

    # Build the full set of targets to scan
    targets = list(_API)
    if enable_reflection:
        targets += _REFLECTION
    for raw in extra_targets:
        parts = raw.split("->", 1)
        if len(parts) == 2:
            cls = parts[0] if parts[0].endswith(";") else parts[0] + ";"
            targets.append(ApiTarget(cls, parts[1], "USER_DEFINED",
                                     f"User-specified target: {raw}"))
        else:
            _warn(f"Ignoring malformed --trace argument: {raw!r}  (expected 'Lclass;->method')")

    seen: set[tuple[str, str, str]] = set()  # (caller_class, caller_method, api_method)

    for api in targets:
        target_ref = f"{api.class_ref}->{api.method}"
        sites = find_callers(dex_files, target_ref)

        for site in sites:
            dedup_key = (site.caller_class, site.caller_method, api.method)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            # ── Reflection branch ──────────────────────────────────────────
            if api.permission == "REFLECTION":
                class_hint, method_hint = None, None
                vals = [v for _, v in site.static_args if v and isinstance(v, str)]
                if vals:
                    class_hint = vals[0]
                if len(vals) > 1:
                    method_hint = vals[1]
                reflection_findings.append(ReflectionFinding(
                    caller_class=site.caller_class,
                    caller_method=site.caller_method,
                    invoke_str=site.invoke_str,
                    line=site.line_number,
                    class_hint=class_hint,
                    method_hint=method_hint,
                ))
                continue

            # ── Resolve effective permission for ContentResolver calls ─────
            effective_perm = api.permission
            uri_hint = None
            if api.permission == "CONTENT_RESOLVER":
                uri_hint = resolve_content_uri(site.static_args)
                if uri_hint:
                    effective_perm, _ = permission_for_uri(uri_hint)
                # (if no URI resolved, keep CONTENT_RESOLVER as-is)

            # ── Reachability check ────────────────────────────────────────
            confirmed, ep, chain = False, None, []
            if not skip_confirm:
                confirmed, ep, chain = reverse_bfs(
                    dex_files, target_ref, entrypoints, max_depth
                )

            # ── Snippet ───────────────────────────────────────────────────
            snippet = ""
            if detail == "snippet":
                snippet = extract_snippet(
                    dex_files, site.caller_class, site.caller_method
                )

            findings.append(Finding(
                api=api,
                effective_permission=effective_perm,
                caller_class=site.caller_class,
                caller_method=site.caller_method,
                call_site_line=site.line_number,
                invoke_str=site.invoke_str,
                confirmed=confirmed,
                entrypoint=ep,
                chain=chain if detail in ("chain", "snippet") else [],
                snippet=snippet,
                uri_hint=uri_hint,
            ))

    return findings, reflection_findings


# ─── Markdown generation ───────────────────────────────────────────────────────

def _fmt(dex_class: str) -> str:
    """Lcom/example/Foo; → com.example.Foo"""
    return dex_class.lstrip("L").rstrip(";").replace("/", ".")


def _render_finding(f: Finding, detail: str, tiers: list[dict]) -> list[str]:
    out: list[str] = []
    cls = _fmt(f.caller_class)
    line_sfx = f":{f.call_site_line}" if f.call_site_line else ""
    confirm_sfx = ""
    if f.confirmed and f.entrypoint:
        ep = f.entrypoint
        confirm_sfx = f" — reachable from `{_fmt(ep.dex_class)}.{ep.method}`"

    perm_disp = f.effective_permission
    if f.uri_hint:
        perm_disp += f" (URI: `{f.uri_hint}`)"

    api_cls = _fmt(f.api.class_ref)
    out.append(f"- **`{cls}.{f.caller_method}`**{line_sfx}{confirm_sfx}")
    out.append(f"  - API: `{api_cls}.{f.api.method}()`")
    out.append(f"  - Data: {f.api.description}")
    if f.api.note:
        out.append(f"  - {f.api.note}")

    if detail in ("chain", "snippet") and f.chain:
        out.append("  <details><summary>📍 Call chain</summary>")
        out.append("")
        out.append("  ```")
        for i, step in enumerate(f.chain):
            # Pretty-print: "Lcom/Foo;->bar" → "com.Foo → bar"
            if "->" in step:
                c, m = step.split("->", 1)
                pretty = f"{_fmt(c)} → {m}"
            else:
                pretty = step
            prefix = "  " if i == 0 else "  ↑ "
            out.append(f"  {prefix}{pretty}")
        out.append("  ```")
        out.append("  </details>")

    if detail == "snippet" and f.snippet:
        out.append("  <details><summary>🔍 Smali snippet</summary>")
        out.append("")
        out.append("  ```smali")
        for sl in f.snippet.splitlines():
            out.append(f"  {sl}")
        out.append("  ```")
        out.append("  </details>")

    return out


def render_markdown(
    pkg: str,
    version: str,
    label: str,
    apk_path: str,
    declared_permissions: list[str],
    findings: list[Finding],
    reflection_findings: list[ReflectionFinding],
    tiers: list[dict],
    detail: str,
) -> str:
    out: list[str] = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    title = label or pkg or Path(apk_path).name

    # ── Header ────────────────────────────────────────────────────────────────
    out += [
        f"# Privacy Audit: {title}",
        "",
        "| | |",
        "|---|---|",
        f"| **Package** | `{pkg}` |",
        f"| **Version** | {version or '—'} |",
        f"| **Analysed** | {now} |",
        f"| **Source** | `{apk_path}` |",
        "",
    ]

    # ── Declared permissions ──────────────────────────────────────────────────
    out += ["## Declared Permissions", ""]
    if not declared_permissions:
        out += ["> No permissions declared in manifest.", ""]
    else:
        rows = sorted(
            [(tier_for(p, tiers), p) for p in declared_permissions],
            key=lambda x: x[0][0],
        )
        out += ["| Permission | Risk |", "|---|---|"]
        for (tidx, tname, emoji), perm in rows:
            out.append(f"| `{perm}` | {emoji} {tname} |")
        out.append("")

    # ── Helper: group findings by tier ────────────────────────────────────────
    def by_tier(flist: list[Finding]):
        groups: dict[int, list[Finding]] = {}
        for f in flist:
            tidx, _, _ = tier_for(f.effective_permission, tiers)
            groups.setdefault(tidx, []).append(f)
        for tidx in sorted(groups):
            if tidx < len(tiers):
                tname = tiers[tidx]["name"]
                emoji = tiers[tidx].get("emoji", "⚪")
            else:
                tname, emoji = "Uncategorised", "⚪"
            yield tidx, tname, emoji, sorted(groups[tidx], key=lambda f: f.caller_class)

    confirmed   = [f for f in findings if f.confirmed]
    potential   = [f for f in findings if not f.confirmed]

    # ── Confirmed data collection ─────────────────────────────────────────────
    out += [
        "---", "",
        "## ✅ Confirmed Data Collection", "",
        "> APIs **reachable from a declared Android entrypoint** — collection is actively occurring.", "",
    ]
    if not confirmed:
        out += ["> None found.", ""]
    else:
        for _, tname, emoji, group in by_tier(confirmed):
            out += [f"### {emoji} {tname}", ""]
            for f in group:
                out += _render_finding(f, detail, tiers)
                out.append("")

    # ── Potential / unconfirmed ───────────────────────────────────────────────
    out += [
        "---", "",
        "## ⚠️ Potential Data Collection", "",
        ("> Sensitive APIs exist in the code but **could not be traced to a concrete "
         "entrypoint**. May be dead code, reached via reflection, or triggered by indirect "
         "dispatch (e.g. dynamic proxy, serialisation, native JNI)."), "",
    ]
    if not potential:
        out += ["> None found.", ""]
    else:
        for _, tname, emoji, group in by_tier(potential):
            out += [f"### {emoji} {tname}", ""]
            for f in group:
                out += _render_finding(f, detail, tiers)
                out.append("")

    # ── Reflection ────────────────────────────────────────────────────────────
    if reflection_findings:
        out += [
            "---", "",
            "## 🔍 Reflection Usage", "",
            ("> Dynamic class loading / method invocation can bypass static analysis. "
             "Manual review is recommended for the following sites."), "",
        ]
        for r in sorted(reflection_findings, key=lambda x: x.caller_class):
            cls = _fmt(r.caller_class)
            line_sfx = f":{r.line}" if r.line else ""
            hint = ""
            if r.class_hint:
                hint = f" → class `{r.class_hint}`"
                if r.method_hint:
                    hint += f", method `{r.method_hint}`"
            out.append(f"- **`{cls}.{r.caller_method}`**{line_sfx}{hint}")
            out.append(f"  `{r.invoke_str}`")
            out.append("")

    # ── Summary ───────────────────────────────────────────────────────────────
    out += [
        "---", "",
        "## Summary", "",
        "| | Count |",
        "|---|---|",
        f"| Declared permissions | {len(declared_permissions)} |",
        f"| Confirmed data-collection sites | {len(confirmed)} |",
        f"| Potential (unconfirmed) sites | {len(potential)} |",
        f"| Reflection usage sites | {len(reflection_findings)} |",
        "",
        "_Generated by `tools/privacy_audit.py` using the [platypus](https://github.com/) analysis library._",
    ]

    return "\n".join(out)


# ─── Logging helpers ──────────────────────────────────────────────────────────

def _info(msg: str) -> None:
    print(f"[*] {msg}", file=sys.stderr)

def _warn(msg: str) -> None:
    print(f"[!] {msg}", file=sys.stderr)


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        prog="privacy_audit.py",
        description="Analyse an Android APK for data-collection behaviour.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("apk", metavar="APK_PATH",
                    help=".apk / .xapk / .apkm / .apks / directory of splits")
    ap.add_argument("--output", "-o", metavar="FILE",
                    help="Write markdown report to FILE (also printed to stdout)")
    ap.add_argument("--detail", choices=["summary", "chain", "snippet"],
                    default="summary",
                    help="Finding detail level — summary (default), chain, or snippet")
    ap.add_argument("--tiers", metavar="JSON",
                    help="Custom tier definition file (JSON array)")
    ap.add_argument("--trace", metavar="CLASS->METHOD", action="append", default=[],
                    help="Extra method to trace, e.g. 'Lcom/example/Analytics;->track' (repeatable)")
    ap.add_argument("--depth", type=int, default=5,
                    help="Call-graph search depth (default: 5)")
    ap.add_argument("--no-confirm", action="store_true",
                    help="Skip entrypoint reachability check — report all findings (faster)")
    ap.add_argument("--reflection", action="store_true",
                    help="Enable reflection detection (Class.forName, Method.invoke, etc.)")
    ap.add_argument("--snippet-lines", type=int, default=10,
                    help="Smali context lines for --detail snippet (default: 10, max 50)")
    args = ap.parse_args()

    _info(f"Loading: {args.apk}")
    apk, pkg, version, label = load_target(args.apk)
    dex_files = get_dex_files(apk)
    _info(f"Package: {pkg or '(unknown)'}  Version: {version or '(unknown)'}  DEX: {len(dex_files)}")

    manifest = get_manifest(apk)
    permissions = extract_permissions(manifest)
    _info(f"Declared permissions: {len(permissions)}")

    tiers = load_tiers(args.tiers)

    entrypoints = []
    if not args.no_confirm:
        entrypoints = extract_entrypoints(manifest, pkg)
        _info(f"Entrypoints identified: {len(entrypoints)}")

    _info(f"Scanning for sensitive API usage (depth={args.depth}, reflection={'on' if args.reflection else 'off'})…")
    findings, reflection = analyse(
        dex_files=dex_files,
        entrypoints=entrypoints,
        extra_targets=args.trace,
        max_depth=args.depth,
        detail=args.detail,
        skip_confirm=args.no_confirm,
        enable_reflection=args.reflection,
    )

    n_confirmed = sum(1 for f in findings if f.confirmed)
    _info(f"Done — {len(findings)} findings ({n_confirmed} confirmed), {len(reflection)} reflection sites")

    md = render_markdown(
        pkg=pkg,
        version=version,
        label=label,
        apk_path=args.apk,
        declared_permissions=permissions,
        findings=findings,
        reflection_findings=reflection,
        tiers=tiers,
        detail=args.detail,
    )

    print(md)

    if args.output:
        Path(args.output).write_text(md, encoding="utf-8")
        _info(f"Report written → {args.output}")


if __name__ == "__main__":
    main()
