# Platypus Scripting API

Scripts run as standard Python 3 with the `platypus` native module available on `sys.path`. One global is injected automatically:

| Global | Type | Description |
|--------|------|-------------|
| `LOADED_APK` | `str \| None` | Filesystem path of the APK currently open in the app, or `None` if none is loaded |

---

## `platypus.Apk`

Parse a single APK file.

```python
import platypus

apk = platypus.Apk(LOADED_APK)          # open from path
apk = platypus.Apk.from_bytes(data)     # open from bytes
```

| Member | Returns | Description |
|--------|---------|-------------|
| `apk.package_name` | `str \| None` | `android:package` from manifest |
| `apk.version_name` | `str \| None` | `android:versionName` |
| `apk.label` | `str \| None` | `<application android:label>` raw value |
| `apk.list_files()` | `list[str]` | All entries in the ZIP |
| `apk.has_file(name)` | `bool` | Check entry existence |
| `apk.read_file(name)` | `bytes` | Raw bytes of any entry |
| `apk.dex_files()` | `list[Dex]` | All DEX files parsed into `Dex` objects |
| `apk.manifest()` | `ManifestNode` | Parsed `AndroidManifest.xml` root node |
| `apk.manifest_resolved()` | `ManifestNode` | Manifest with `@string/...` refs substituted |
| `apk.resources()` | `ResourceTable` | Parsed `resources.arsc` |
| `apk.drawables()` | `list[str]` | Paths matching `res/drawable*` |
| `apk.layouts()` | `list[str]` | Paths matching `res/layout*` |

---

## `platypus.ApkSet`

Handle split APKs (base + feature/density/ABI splits).

```python
apk_set = platypus.ApkSet.from_dir("/path/to/splits/")
apk_set = platypus.ApkSet.from_files(["base.apk", "split_config.arm64.apk"])
apk_set = platypus.ApkSet.from_bytes_list([("base.apk", base_bytes), ...])
```

| Member | Returns | Description |
|--------|---------|-------------|
| `apk_set.split_count` | `int` | Number of splits |
| `apk_set.split_names()` | `list[str]` | Names of each split |
| `apk_set.list_all_files()` | `list[tuple[str,str]]` | `(split_name, file_path)` pairs |
| `apk_set.dex_files()` | `list[Dex]` | All DEX across all splits |
| `apk_set.read_file(name)` | `bytes` | Read from base APK first, then splits |
| `apk_set.has_file(name)` | `bool` | Exists in any split? |
| `apk_set.manifest()` | `ManifestNode` | Base APK manifest |
| `apk_set.manifest_resolved()` | `ManifestNode` | Resolved manifest |
| `apk_set.resources()` | `ResourceTable` | Base APK resources |
| `apk_set.package_name` | `str \| None` | |
| `apk_set.version_name` | `str \| None` | |
| `apk_set.drawables()` | `list[tuple[str,str]]` | `(split_name, path)` pairs |
| `apk_set.layouts()` | `list[tuple[str,str]]` | `(split_name, path)` pairs |

---

## `platypus.Dex`

Parse and analyse a DEX file directly.

```python
dex = platypus.Dex.from_file("classes.dex")
dex = platypus.Dex.from_bytes(data, "classes.dex")

# or grab from an APK:
dex = platypus.Apk(LOADED_APK).dex_files()[0]
```

| Member | Returns | Description |
|--------|---------|-------------|
| `dex.filename` | `str` | Name used when the dex was loaded |
| `dex.sha256` | `str` | Hex SHA-256 digest |
| `dex.version` | `str` | DEX version string e.g. `"035"` |
| `dex.class_count` | `int` | Number of class definitions |
| `dex.class_names()` | `list[str]` | All type descriptors e.g. `"Lcom/example/Foo;"` |
| `dex.decompile_class(class_name)` | `str` | Java-like decompiled source |
| `dex.disassemble_class(class_name)` | `str` | Smali disassembly |
| `dex.find_calls(target)` | `list[CallSite]` | All call sites invoking `target` |
| `dex.exec_method(target, args, resources=None)` | `str \| None` | Execute a method once and return the formatted result |
| `dex.find_exec(target, resources=None)` | `list[ExecResult]` | Find all call sites for `target` and execute each one |

`target` format everywhere: `"Lpackage/ClassName;->methodName"`

---

## `platypus.Vm`

A stateful Dalvik VM interpreter. Use this when you need custom mocks, multi-DEX execution, or repeated calls.

```python
vm = platypus.Vm()
vm.load_dex_file("classes.dex")
vm.load_resources(platypus.Apk(LOADED_APK).resources())
```

| Member | Returns | Description |
|--------|---------|-------------|
| `vm.load_dex_file(path)` | `None` | Add a DEX file from disk |
| `vm.load_dex_bytes(data, name)` | `None` | Add a DEX file from bytes |
| `vm.load_resources(rt)` | `None` | Preload `ResourceTable` so `getString(int)` calls resolve |
| `vm.register_mock(method_fqn, fn)` | `None` | Register a Python function as a mock for a DEX method |
| `vm.exec_method(target, args)` | `str \| None` | Execute a method and return the formatted result |
| `vm.reset(instr_limit)` | `None` | Clear call stack; set instruction budget for next call |

### Mock type mapping

Dalvik types are converted to/from Python automatically:

| Dalvik | Python |
|--------|--------|
| `int` / `long` | `int` |
| `float` / `double` | `float` |
| `boolean` | `bool` |
| `String` | `str` |
| `byte[]` | `bytes` |
| arrays | `list` |
| `null` / other | `None` |

```python
# Catch-all mock — fires for all overloads of the method
vm.register_mock(
    "Landroid/content/Context;->getString",
    lambda res_id: f"mock_string_{res_id}"
)

# Specific overload only (include full descriptor)
vm.register_mock(
    "Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I",
    lambda s: int(s)
)

# Override a built-in mock
import base64
vm.register_mock(
    "Landroid/util/Base64;->decode",
    lambda data, flags: base64.b64decode(data)
)
```

---

## Argument encoding for `exec_method` / `find_exec`

`args` is always `list[str]`. The engine decodes each string:

| Format | Meaning |
|--------|---------|
| `"42"` | Integer literal |
| `"0x7f040001"` | Hex integer (resource ID etc.) |
| `'"hello"'` | String literal (inner quotes required) |
| `"@sget:Lcom/Foo;->FIELD:I"` | Static field get — value read from VM state |
| `"@invoke!Lcom/Foo;->method()"` | Result of calling a helper method |

These encodings are produced automatically by `find_exec` from the static args it finds at each call site — you rarely need to write them by hand.

---

## `platypus.ManifestNode`

A tree node from a parsed `AndroidManifest.xml`.

```python
root = apk.manifest()
print(root.tag)                          # "manifest"
print(root.attr("package"))              # "com.example.app"
print(root.attrs())                      # {"package": "com.example.app", ...}

for activity in root.find_all("activity"):
    print(activity.attr("android:name"))

app = root.find_first("application")
print(app.to_xml())
```

| Member | Returns | Description |
|--------|---------|-------------|
| `node.tag` | `str` | XML element tag name |
| `node.attr(name)` | `str \| None` | Single attribute value |
| `node.attrs()` | `dict[str,str]` | All attributes |
| `node.children()` | `list[ManifestNode]` | Direct children |
| `node.find_all(tag)` | `list[ManifestNode]` | All descendants with this tag |
| `node.find_first(tag)` | `ManifestNode \| None` | First descendant with this tag |
| `node.to_xml()` | `str` | Serialize back to XML string |

---

## `platypus.ResourceTable`

Parsed `resources.arsc`.

```python
res = apk.resources()
print(res.string_by_name("app_name"))    # "My App"
print(res.get_string(0x7f040001))        # raw string at that ID
print(res.resolve(0x7f040001))           # follows reference chains
```

| Member | Returns | Description |
|--------|---------|-------------|
| `res.get(res_id)` | `Resource \| None` | Full entry by numeric ID |
| `res.get_string(res_id)` | `str \| None` | String value at ID (no reference chasing) |
| `res.resolve(res_id)` | `str \| None` | Resolve ID, following `@ref/...` chains |
| `res.string_by_name(name)` | `str \| None` | Look up `@string/name` |
| `res.all_resources()` | `list[Resource]` | Every entry in the table |
| `res.by_type(type_name)` | `list[Resource]` | Filter by type e.g. `"string"`, `"drawable"` |
| `res.strings()` | `list[Resource]` | Shorthand for `by_type("string")` |

### `Resource` fields

| Field | Type | Description |
|-------|------|-------------|
| `r.id` | `int` | Numeric resource ID |
| `r.name` | `str` | Resource name e.g. `"app_name"` |
| `r.type_name` | `str` | Type bucket e.g. `"string"`, `"drawable"` |
| `r.value` | `str` | String representation of the value |

---

## `platypus.CallSite`

Returned by `Dex.find_calls()`.

| Field | Type | Description |
|-------|------|-------------|
| `site.caller_class` | `str` | Class containing the call |
| `site.caller_method` | `str` | Method containing the call |
| `site.source_file` | `str` | Source file name if present |
| `site.line_number` | `int \| None` | Line number if debug info present |
| `site.invoke_str` | `str` | Full Smali invoke instruction |
| `site.static_args` | `list[tuple[int, str\|None]]` | `(register_index, constant_value)` — `None` when the value isn't statically known |

---

## `platypus.ExecResult`

Returned by `Dex.find_exec()`.

| Field | Type | Description |
|-------|------|-------------|
| `r.site` | `CallSite` | The call site that was executed |
| `r.result` | `str \| None` | Formatted return value, `None` if void or not resolvable |

---

## Examples

### Enumerate classes and decompile one

```python
import platypus

apk = platypus.Apk(LOADED_APK)
dex = apk.dex_files()[0]

print(f"{dex.class_count} classes in {dex.filename}")
for name in dex.class_names()[:10]:
    print(name)

src = dex.decompile_class("Lcom/example/MainActivity;")
print(src)
```

### Find all call sites for a method

```python
import platypus

dex   = platypus.Apk(LOADED_APK).dex_files()[0]
sites = dex.find_calls("Landroid/util/Log;->d")

for site in sites:
    print(f"{site.caller_class}->{site.caller_method}:{site.line_number}")
    print(f"  {site.invoke_str}")
```

### Execute all call sites and collect results

```python
import platypus

apk = platypus.Apk(LOADED_APK)
res = apk.resources()
dex = apk.dex_files()[0]

for r in dex.find_exec("Landroid/content/Context;->getString", resources=res):
    if r.result:
        print(f"{r.site.caller_class}:{r.site.line_number}  →  {r.result!r}")
```

### Custom VM with mocks to decrypt strings

```python
import platypus, base64

apk = platypus.Apk(LOADED_APK)
vm  = platypus.Vm()

for dex in apk.dex_files():
    vm.load_dex_bytes(apk.read_file(dex.filename), dex.filename)

vm.load_resources(apk.resources())

vm.register_mock(
    "Lcom/example/util/Obf;->decrypt",
    lambda ciphertext: base64.b64decode(ciphertext).decode()
)

result = vm.exec_method("Lcom/example/Config;->getServerUrl", [])
print(result)
```

### Inspect manifest permissions and activities

```python
import platypus

manifest = platypus.Apk(LOADED_APK).manifest_resolved()

print("Package:", manifest.attr("package"))

perms = manifest.find_all("uses-permission")
print(f"\n{len(perms)} permissions:")
for p in perms:
    print(" ", p.attr("android:name"))

activities = manifest.find_all("activity")
print(f"\n{len(activities)} activities:")
for a in activities:
    print(" ", a.attr("android:name"))
```

### Enumerate all string resources

```python
import platypus

res = platypus.Apk(LOADED_APK).resources()

for r in res.strings():
    print(f"0x{r.id:08x}  {r.name:40s}  {r.value!r}")
```

---

## Editor shortcuts

| Shortcut | Action |
|----------|--------|
| `⌘↩` / `Ctrl+↩` | Run script |
| `Tab` / `Shift+Tab` | Indent / dedent selection |
| `⌘Z` / `Ctrl+Z` | Undo |

**Completions** fire as you type. After `import platypus`, type `platypus.` to see all top-level members. Type `apk.`, `dex.`, `vm.`, `manifest.`, or `res.` for member completions — the editor infers types from assignments in the current script and from common variable name patterns (`apk`, `dex`, `vm`, `manifest`, `res`, `resource_table`, `site`, `result`, etc.).
