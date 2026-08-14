// ─── Token types ─────────────────────────────────────────────────────────────

export type TokenType =
  | "keyword"
  | "directive"
  | "opcode"
  | "string"
  | "comment"
  | "type"
  | "number"
  | "register"
  | "label"
  | "annotation"
  | "xref"
  | "plain";

export interface Token {
  type: TokenType;
  text: string;
  target?: string; // For xref tokens – what to navigate to
}

export type TokenizedLine = Token[];

// ─── Class-name index for varName.method() xref promotion ─────────────────

/** A lightweight lookup table used by the Java tokenizer to resolve a
 *  variable receiver back to a project class. Two name-shapes are
 *  supported in lookups:
 *
 *  * `wfg` → `Lhivhi/wfg;` — Dalvik obfuscators commonly name the local
 *    after the lowercased class simple-name. We match by indexing the
 *    simple-name lowercased.
 *  * `mainActivity` → `LMainActivity;` — jadx-style camelCase locals.
 *    We match by lowercasing the FIRST character of the simple-name
 *    and indexing.
 *
 *  When both keys collide (rare — e.g. a class named `Wfg` would map
 *  to `wfg` under both rules), the later insert wins; that's
 *  consistent with the Object.entries iteration order of the tree
 *  builder.
 *
 *  The class names stored as values are the normalised stripped form
 *  (`com/foo/Bar`, no `L`/`;`) — same shape as `node.fullName` in the
 *  tree and `tab.className` in the open-tabs list. `handleXrefClick`
 *  in CenterPanel re-wraps to `L…;` before passing to
 *  `navigateToMember`. */
export type ClassIndex = Map<string, string>;

/** A per-document import map: bare simple-name → full slash-separated
 *  class path (`com/foo/Bar`, no `L`/`;`). Built from the active tab's
 *  `import com.foo.Bar;` lines.
 *
 *  Used to disambiguate variable-receiver method calls when multiple
 *  classes in the project share a simple name (very common in obfuscated
 *  APKs — `wfg` might live under both `hivhi/` and `something/`). When
 *  the active class explicitly imports `hivhi.wfg`, that's an
 *  authoritative resolution for `wfg.foo(...)` in this file —
 *  authoritative in a way that the project-wide [`ClassIndex`] cannot
 *  be, since the index is "last writer wins" on simple-name collisions.
 *
 *  Resolution priority used by the tokenizer:
 *    1. Import map (this) — exact match for this file
 *    2. ClassIndex — project-wide fallback when no import matches
 *    3. None — render as plain text */
export type ImportMap = Map<string, string>;

/** Parse `import …;` lines out of a Java source string and produce a
 *  simple-name → slash-path lookup.
 *
 *  Format expected (matches our decompiler output):
 *    `import com.example.Foo;`
 *    `import   com.example.Foo  ;`     (loose whitespace tolerated)
 *    `import static com.example.Foo.bar;`  (static imports ignored —
 *                                            they're method/field refs)
 *
 *  Inner classes (`com.example.Foo$Inner`) are indexed under both the
 *  outer simple name (`Foo`) and the inner name (`Inner`) so either
 *  form resolves; static qualifying is handled by the receiver match
 *  inside the tokenizer. */
export function buildImportMap(code: string): ImportMap {
  const map: ImportMap = new Map();
  // Conservative regex: must be at line start, followed by whitespace,
  // optionally `static`, then a dotted path, semicolon. We don't
  // attempt to parse multi-line imports (the decompiler never emits
  // them).
  const re = /^\s*import\s+(static\s+)?([a-zA-Z_$][\w$.]*)\s*;/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(code)) !== null) {
    const isStatic = !!m[1];
    const dotted = m[2];
    const segs = dotted.split(".");
    let classIdx: number;
    if (isStatic) {
      // `import static a.b.C.foo;` — the trailing segment(s) are the
      // imported member(s); the class is the last segment that starts
      // with an uppercase letter.
      classIdx = -1;
      for (let i = segs.length - 1; i >= 0; i--) {
        if (/^[A-Z]/.test(segs[i])) {
          classIdx = i;
          break;
        }
      }
      if (classIdx === -1) continue; // can't tell which segment is the class
    } else {
      // Plain type import — the last segment IS the class, regardless of
      // case. Obfuscated APKs routinely use all-lowercase class names
      // (`import hivhi.wfg;`); an uppercase heuristic would wrongly skip
      // them and lose the authoritative resolution for `wfg.foo(...)`.
      classIdx = segs.length - 1;
    }
    const classPath = segs.slice(0, classIdx + 1).join("/");
    const className = segs[classIdx];
    // Index under the bare class name + lowercased forms so we match
    // both `Foo.bar(...)` and the camelCase-local convention
    // `foo.bar(...)`.
    map.set(className, classPath);
    map.set(className.toLowerCase(), classPath);
    const camel = className.charAt(0).toLowerCase() + className.slice(1);
    if (camel !== className.toLowerCase()) {
      map.set(camel, classPath);
    }
  }
  return map;
}

/** Build a [`ClassIndex`] from the project's full list of known class
 *  paths (`com/foo/Bar`, no `L`/`;`). Indexes each class under both
 *  the lowercased simple-name and the lowercased-first-char
 *  simple-name (when those differ — for an already-lowercase class
 *  there's only one entry).
 *
 *  Two-pass over O(classes) — cheap to recompute on every tree
 *  refresh.
 */
export function buildClassIndex(allClasses: Iterable<string>): ClassIndex {
  const idx: ClassIndex = new Map();
  for (const full of allClasses) {
    const slashIdx = full.lastIndexOf("/");
    const simple = slashIdx === -1 ? full : full.slice(slashIdx + 1);
    // Strip a trailing `;` defensively in case a caller passes the
    // wrapped form. We don't strip a leading `L` because
    // single-letter classes (`Lo;`) would lose the `L` incorrectly.
    const cleaned = simple.replace(/;$/, "");
    if (cleaned.length === 0) continue;

    const lower = cleaned.toLowerCase();
    // Lowercased-first-char form (matches `mainActivity` for
    // `MainActivity`). Only distinct from `lower` when the class name has
    // more than a leading capital.
    const camelKey = cleaned.charAt(0).toLowerCase() + cleaned.slice(1);

    // Form 1: lowercased simple-name (matches `wfg` for `Lhivhi/wfg;`).
    // Form 2: lowercased-first-char.
    // Both are project-wide and last-writer-wins on simple-name
    // collisions — they're the fallback when nothing more specific hits.
    idx.set(lower, full);
    if (camelKey !== lower) idx.set(camelKey, full);

    // Package-qualified forms (`hivhi/wfg`). A package can't hold two
    // classes with the same simple name, so these keys are effectively
    // collision-free. The tokenizer tries them first for same-package
    // receivers, which is what fixes the "wrong class on wfg.bihvbhi(...)"
    // jump: same-package / self references emit no `import`, so without a
    // package-qualified hit they fell through to the last-writer-wins
    // simple-name entry and could land on a same-named class in another
    // package (rampant in obfuscated APKs).
    if (slashIdx !== -1) {
      const pkgLower = full.slice(0, slashIdx).toLowerCase();
      idx.set(pkgLower + "/" + lower, full);
      if (camelKey !== lower) idx.set(pkgLower + "/" + camelKey, full);
    }
  }
  return idx;
}

// ─── Smali keywords / sets ───────────────────────────────────────────────────

const SMALI_DIRECTIVES = new Set([
  ".class",
  ".super",
  ".source",
  ".field",
  ".method",
  ".end",
  ".implements",
  ".annotation",
  ".registers",
  ".locals",
  ".line",
  ".prologue",
  ".epilogue",
  ".param",
  ".restart",
  ".packed-switch",
  ".sparse-switch",
  ".array-data",
  ".catchall",
  ".catch",
  ".parameter",
  ".parametp",
]);

const SMALI_OPCODE_PREFIXES = [
  "invoke-",
  "const-",
  "move",
  "return",
  "iget",
  "iput",
  "sget",
  "sput",
  "aget",
  "aput",
  "goto",
  "if-",
  "add-",
  "sub-",
  "mul-",
  "div-",
  "rem-",
  "and-",
  "or-",
  "xor-",
  "shl-",
  "shr-",
  "ushr-",
  "neg-",
  "not-",
  "int-to-",
  "long-to-",
  "float-to-",
  "double-to-",
  "new-instance",
  "new-array",
  "filled-new-array",
  "fill-array-data",
  "check-cast",
  "instance-of",
  "array-length",
  "throw",
  "monitor-enter",
  "monitor-exit",
  "cmpl-",
  "cmpg-",
  "cmp-",
  "nop",
  "packed-switch",
  "sparse-switch",
];

const SMALI_ACCESS_FLAGS = new Set([
  "public",
  "private",
  "protected",
  "static",
  "final",
  "synchronized",
  "bridge",
  "varargs",
  "native",
  "abstract",
  "strictfp",
  "synthetic",
  "constructor",
  "declared-synchronized",
  "interface",
  "enum",
  "annotation",
  "volatile",
  "transient",
]);

// ─── Java keywords ───────────────────────────────────────────────────────────

const JAVA_KEYWORDS = new Set([
  "abstract",
  "assert",
  "boolean",
  "break",
  "byte",
  "case",
  "catch",
  "char",
  "class",
  "const",
  "continue",
  "default",
  "do",
  "double",
  "else",
  "enum",
  "extends",
  "final",
  "finally",
  "float",
  "for",
  "goto",
  "if",
  "implements",
  "import",
  "instanceof",
  "int",
  "interface",
  "long",
  "native",
  "new",
  "package",
  "private",
  "protected",
  "public",
  "return",
  "short",
  "static",
  "strictfp",
  "super",
  "switch",
  "synchronized",
  "this",
  "throw",
  "throws",
  "transient",
  "try",
  "void",
  "volatile",
  "while",
  "true",
  "false",
  "null",
  "var",
  "record",
  "sealed",
  "permits",
  "yield",
]);

// ─── Regex helpers ────────────────────────────────────────────────────────────

// Dalvik descriptor: Lcom/example/Foo; or [[B etc.
const DALVIK_TYPE_RE = /L([a-zA-Z_$][a-zA-Z0-9_$]*(?:\/[a-zA-Z_$][a-zA-Z0-9_$]*)*);/g;

// Java class name (capitalized, dotted)
const JAVA_CLASS_RE = /\b([A-Z][a-zA-Z0-9_$]*(?:\.[A-Z][a-zA-Z0-9_$]*)*)\b/g;

// Register: v0-vN or p0-pN
const REGISTER_RE = /\b([vp]\d+)\b/g;

// Number: hex or decimal
const NUMBER_RE = /\b(0x[0-9a-fA-F]+|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?[fFdDlL]?)\b/g;

// ─── Java dotted-path → Dalvik path helper ───────────────────────────────────

/**
 * Convert a Java dotted class reference to a Dalvik-style path.
 * Package segments (lowercase) use '/' as separator.
 * Once an uppercase segment is encountered (a class name), subsequent
 * segments are inner classes and use '$' as separator.
 *
 * Examples:
 *   com.example.Foo        → com/example/Foo
 *   com.example.Foo.Bar    → com/example/Foo$Bar
 *   HmApplication.bdogw   → HmApplication$bdogw
 */
export function javaRefToPath(dotted: string): string {
  const segs = dotted.split(".");
  let result = segs[0];
  let seenClass = /^[A-Z]/.test(segs[0]);
  for (let i = 1; i < segs.length; i++) {
    result += seenClass ? "$" : "/";
    result += segs[i];
    if (/^[A-Z]/.test(segs[i])) seenClass = true;
  }
  return result;
}

// ─── Core tokeniser functions ─────────────────────────────────────────────────

function isSmaliOpcode(word: string): boolean {
  const lower = word.toLowerCase();
  return SMALI_OPCODE_PREFIXES.some((p) => lower.startsWith(p));
}

function isSmaliDirective(word: string): boolean {
  return SMALI_DIRECTIVES.has(word);
}

/** Split a string into segments, marking positions of regex matches. */
function splitByRegex(
  text: string,
  re: RegExp,
  makeToken: (match: RegExpExecArray) => Token
): Token[] {
  const tokens: Token[] = [];
  let lastIdx = 0;
  re.lastIndex = 0;
  let m: RegExpExecArray | null;

  while ((m = re.exec(text)) !== null) {
    if (m.index > lastIdx) {
      tokens.push({ type: "plain", text: text.slice(lastIdx, m.index) });
    }
    tokens.push(makeToken(m));
    lastIdx = m.index + m[0].length;
  }

  if (lastIdx < text.length) {
    tokens.push({ type: "plain", text: text.slice(lastIdx) });
  }

  return tokens;
}

// ─── Smali tokenizer ─────────────────────────────────────────────────────────

export function tokenizeSmaliLine(line: string): TokenizedLine {
  const tokens: Token[] = [];

  // Handle full-line comment (#)
  const commentHashIdx = line.indexOf("#");
  let codePart = line;
  let commentPart: string | null = null;

  // Be careful: # may appear inside strings
  // Simple heuristic: find first # that's not inside a quoted string
  let inStr = false;
  let strChar = "";
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inStr) {
      if (c === strChar && line[i - 1] !== "\\") inStr = false;
    } else {
      if (c === '"' || c === "'") {
        inStr = true;
        strChar = c;
      } else if (c === "#") {
        codePart = line.slice(0, i);
        commentPart = line.slice(i);
        break;
      }
    }
  }

  // Tokenize the code portion word by word / segment by segment
  // We'll scan character-by-character for simplicity and correctness
  let i = 0;
  while (i < codePart.length) {
    // Whitespace
    if (/\s/.test(codePart[i])) {
      let j = i;
      while (j < codePart.length && /\s/.test(codePart[j])) j++;
      tokens.push({ type: "plain", text: codePart.slice(i, j) });
      i = j;
      continue;
    }

    // String literal
    if (codePart[i] === '"') {
      let j = i + 1;
      while (j < codePart.length) {
        if (codePart[j] === '"' && codePart[j - 1] !== "\\") {
          j++;
          break;
        }
        j++;
      }
      tokens.push({ type: "string", text: codePart.slice(i, j) });
      i = j;
      continue;
    }

    // Dalvik type descriptor (L...;) — optionally followed by ->methodName
    if (codePart[i] === "L") {
      const rest = codePart.slice(i);
      const typeMatch = rest.match(/^(L[a-zA-Z_$][a-zA-Z0-9_$]*(?:\/[a-zA-Z0-9_$]+)*;)/);
      if (typeMatch) {
        const raw = typeMatch[1];
        tokens.push({ type: "xref", text: raw, target: raw });
        i += raw.length;
        // Check for method reference: ->methodName
        if (codePart.slice(i, i + 2) === "->") {
          tokens.push({ type: "plain", text: "->" });
          i += 2;
          let j = i;
          while (j < codePart.length && /[a-zA-Z0-9_$<>]/.test(codePart[j])) j++;
          if (j > i) {
            const methodName = codePart.slice(i, j);
            tokens.push({ type: "xref", text: methodName, target: `${raw}->${methodName}` });
            i = j;
          }
        }
        continue;
      }
    }

    // Array type descriptors starting with [
    if (codePart[i] === "[") {
      let j = i;
      while (j < codePart.length && codePart[j] === "[") j++;
      if (j < codePart.length && "BCDFIJSZ".includes(codePart[j])) {
        j++;
        tokens.push({ type: "type", text: codePart.slice(i, j) });
        i = j;
        continue;
      }
      if (j < codePart.length && codePart[j] === "L") {
        const rest = codePart.slice(j);
        const typeMatch = rest.match(/^(L[a-zA-Z_$][a-zA-Z0-9_$]*(?:\/[a-zA-Z0-9_$]+)*;)/);
        if (typeMatch) {
          const full = codePart.slice(i, j) + typeMatch[1];
          tokens.push({ type: "xref", text: full, target: typeMatch[1] });
          i += full.length;
          continue;
        }
      }
    }

    // Directive (.something)
    if (codePart[i] === ".") {
      let j = i + 1;
      while (j < codePart.length && /[a-zA-Z0-9\-_]/.test(codePart[j])) j++;
      const word = codePart.slice(i, j);
      if (isSmaliDirective(word)) {
        tokens.push({ type: "directive", text: word });
      } else {
        tokens.push({ type: "plain", text: word });
      }
      i = j;
      continue;
    }

    // Label (:something)
    if (codePart[i] === ":") {
      let j = i + 1;
      while (j < codePart.length && /[a-zA-Z0-9_]/.test(codePart[j])) j++;
      tokens.push({ type: "label", text: codePart.slice(i, j) });
      i = j;
      continue;
    }

    // Register (v0, p0, etc.)
    if ((codePart[i] === "v" || codePart[i] === "p") && /\d/.test(codePart[i + 1] ?? "")) {
      let j = i + 1;
      while (j < codePart.length && /\d/.test(codePart[j])) j++;
      const word = codePart.slice(i, j);
      // Make sure it's not part of a longer identifier
      const nextChar = codePart[j];
      if (!nextChar || !/[a-zA-Z_$]/.test(nextChar)) {
        tokens.push({ type: "register", text: word });
        i = j;
        continue;
      }
    }

    // Number (hex or decimal)
    if (/\d/.test(codePart[i]) || (codePart[i] === "-" && /\d/.test(codePart[i + 1] ?? ""))) {
      let j = i;
      if (codePart[j] === "-") j++;
      if (codePart.slice(j, j + 2) === "0x" || codePart.slice(j, j + 2) === "0X") {
        j += 2;
        while (j < codePart.length && /[0-9a-fA-F]/.test(codePart[j])) j++;
      } else {
        while (j < codePart.length && /[0-9]/.test(codePart[j])) j++;
        if (codePart[j] === ".") {
          j++;
          while (j < codePart.length && /[0-9]/.test(codePart[j])) j++;
        }
        if (/[eE]/.test(codePart[j] ?? "")) {
          j++;
          if (/[+-]/.test(codePart[j] ?? "")) j++;
          while (j < codePart.length && /[0-9]/.test(codePart[j])) j++;
        }
        if (/[fFdDlL]/.test(codePart[j] ?? "")) j++;
      }
      tokens.push({ type: "number", text: codePart.slice(i, j) });
      i = j;
      continue;
    }

    // Word (opcode, access flag, or plain)
    if (/[a-zA-Z_$]/.test(codePart[i])) {
      let j = i;
      while (j < codePart.length && /[a-zA-Z0-9_$\-]/.test(codePart[j])) j++;
      const word = codePart.slice(i, j);

      if (isSmaliOpcode(word)) {
        tokens.push({ type: "opcode", text: word });
      } else if (SMALI_ACCESS_FLAGS.has(word)) {
        tokens.push({ type: "keyword", text: word });
      } else if (word === "V" || word === "Z" || word === "B" || word === "C" || word === "I" || word === "J" || word === "F" || word === "D" || word === "S") {
        // Primitive Dalvik type
        tokens.push({ type: "type", text: word });
      } else {
        tokens.push({ type: "plain", text: word });
      }
      i = j;
      continue;
    }

    // Anything else: plain single character
    tokens.push({ type: "plain", text: codePart[i] });
    i++;
  }

  // Add comment portion
  if (commentPart) {
    tokens.push({ type: "comment", text: commentPart });
  }

  return tokens;
}

// ─── Java tokenizer ──────────────────────────────────────────────────────────

/**
 * Tokenize one Java line.
 *
 * `currentClass` (optional, normalized like `"com/foo/Bar"`) is used to
 * promote `this.methodName(` patterns into clickable xrefs that target
 * the current class.
 *
 * `classIndex` (optional) is the project-wide name→fqcn lookup table.
 * Used as a FALLBACK to promote `varName.method(` into xrefs when
 * the active doc's imports don't disambiguate. Last-writer-wins on
 * simple-name collisions — see [`ClassIndex`].
 *
 * `importMap` (optional) is the per-doc import lookup. Authoritative
 * for the active file: when the source has `import hivhi.wfg;`, this
 * map resolves `wfg.foo(...)` to `Lhivhi/wfg;->foo` regardless of how
 * many other classes named `wfg` exist project-wide. Built once per
 * tab via [`buildImportMap`]. This is the fix for the bug where xref
 * clicks jumped to the wrong class on obfuscated APKs that re-use
 * short class names across packages.
 */
export function tokenizeJavaLine(
  line: string,
  multilineCommentOpen: boolean,
  currentClass?: string,
  classIndex?: ClassIndex,
  importMap?: ImportMap,
  /** Set of every known fully-qualified class path (slash form, e.g.
   *  `hivhi/wfg`). Lets the tokenizer resolve fully-qualified method
   *  calls whose path has no uppercase segment — the decompiler emits
   *  these for classes whose simple name is ambiguous across packages
   *  (e.g. `hivhi.wfg.bihvbhi(...)`). Without it those all-lowercase
   *  FQNs wouldn't be recognised as class references. */
  classPaths?: Set<string>,
): { tokens: TokenizedLine; multilineCommentOpen: boolean } {
  const tokens: Token[] = [];
  let i = 0;
  let inMultiline = multilineCommentOpen;

  if (inMultiline) {
    // Look for end of multiline comment
    const endIdx = line.indexOf("*/");
    if (endIdx === -1) {
      tokens.push({ type: "comment", text: line });
      return { tokens, multilineCommentOpen: true };
    } else {
      tokens.push({ type: "comment", text: line.slice(0, endIdx + 2) });
      i = endIdx + 2;
      inMultiline = false;
    }
  }

  while (i < line.length) {
    // Whitespace
    if (/\s/.test(line[i])) {
      let j = i;
      while (j < line.length && /\s/.test(line[j])) j++;
      tokens.push({ type: "plain", text: line.slice(i, j) });
      i = j;
      continue;
    }

    // Single-line comment
    if (line[i] === "/" && line[i + 1] === "/") {
      tokens.push({ type: "comment", text: line.slice(i) });
      i = line.length;
      continue;
    }

    // Multi-line comment start
    if (line[i] === "/" && line[i + 1] === "*") {
      const endIdx = line.indexOf("*/", i + 2);
      if (endIdx === -1) {
        tokens.push({ type: "comment", text: line.slice(i) });
        return { tokens, multilineCommentOpen: true };
      } else {
        tokens.push({ type: "comment", text: line.slice(i, endIdx + 2) });
        i = endIdx + 2;
        continue;
      }
    }

    // String literal
    if (line[i] === '"') {
      let j = i + 1;
      while (j < line.length) {
        if (line[j] === '"' && line[j - 1] !== "\\") {
          j++;
          break;
        }
        j++;
      }
      tokens.push({ type: "string", text: line.slice(i, j) });
      i = j;
      continue;
    }

    // Char literal
    if (line[i] === "'") {
      let j = i + 1;
      while (j < line.length) {
        if (line[j] === "'" && line[j - 1] !== "\\") {
          j++;
          break;
        }
        j++;
      }
      tokens.push({ type: "string", text: line.slice(i, j) });
      i = j;
      continue;
    }

    // Number
    if (/\d/.test(line[i]) || (line[i] === "-" && /\d/.test(line[i + 1] ?? "") && (i === 0 || /[\s(=,]/.test(line[i - 1])))) {
      let j = i;
      if (line[j] === "-") j++;
      if (line.slice(j, j + 2).toLowerCase() === "0x") {
        j += 2;
        while (j < line.length && /[0-9a-fA-F_]/.test(line[j])) j++;
      } else {
        while (j < line.length && /[0-9_]/.test(line[j])) j++;
        if (line[j] === ".") {
          j++;
          while (j < line.length && /[0-9_]/.test(line[j])) j++;
        }
        if (/[eE]/.test(line[j] ?? "")) {
          j++;
          if (/[+-]/.test(line[j] ?? "")) j++;
          while (j < line.length && /[0-9]/.test(line[j])) j++;
        }
        if (/[fFdDlL]/.test(line[j] ?? "")) j++;
      }
      tokens.push({ type: "number", text: line.slice(i, j) });
      i = j;
      continue;
    }

    // Annotation
    if (line[i] === "@") {
      let j = i + 1;
      while (j < line.length && /[a-zA-Z0-9_$]/.test(line[j])) j++;
      tokens.push({ type: "annotation", text: line.slice(i, j) });
      i = j;
      continue;
    }

    // Word (keyword, type, or identifier)
    if (/[a-zA-Z_$]/.test(line[i])) {
      let j = i;
      while (j < line.length && /[a-zA-Z0-9_$]/.test(line[j])) j++;
      const word = line.slice(i, j);

      // Check for fully-qualified class name (e.g., com.example.Foo)
      // Look ahead for dots
      let longWord = word;
      let k = j;
      while (k < line.length && line[k] === "." && /[a-zA-Z_$]/.test(line[k + 1] ?? "")) {
        let m = k + 1;
        while (m < line.length && /[a-zA-Z0-9_$]/.test(line[m])) m++;
        const segment = line.slice(k + 1, m);
        longWord += "." + segment;
        k = m;
      }

      // If dotted and followed by '(' → it's a method call xref.
      //
      // Four cases handled, in priority order:
      //   1. `this.methodName(` — same-class call. Targets `currentClass`.
      //   2. `Activity.foo(` (uppercase first segment) — qualified
      //      static / type method. Targets the literal class path.
      //   3. `varName.method(` where `varName` resolves to a known
      //      project class via the lookup heuristics (`wfg` →
      //      `Lhivhi/wfg;`, `mainActivity` → `MainActivity`).
      //      Targets that class. **This is what makes lowercase-
      //      receiver method calls clickable** — without the index
      //      lookup we can't tell `wfg.fi(...)` from `str.toLowerCase()`.
      //   4. All other variable receivers — fall through to
      //      plain-text tokens (no xref).
      if (longWord.length > word.length && k < line.length && line[k] === "(") {
        const lastDot = longWord.lastIndexOf(".");
        const classPart = longWord.slice(0, lastDot);
        const methodPart = longWord.slice(lastDot + 1);

        if (classPart === "this" && currentClass) {
          tokens.push({
            type: "xref",
            text: longWord,
            target: `${currentClass}->${methodPart}`,
          });
          i = k; // leave '(' to be processed normally
          continue;
        }

        // Fully-qualified call whose dotted prefix is an exact known class
        // path. This is authoritative — the source carries the full path —
        // and is the only thing that resolves all-lowercase FQNs like
        // `hivhi.wfg.bihvbhi(...)` that the decompiler emits for classes
        // with an ambiguous simple name. Checked before the uppercase
        // heuristic so an exact path match always wins.
        if (classPart.includes(".") && classPaths) {
          const path = javaRefToPath(classPart);
          if (classPaths.has(path)) {
            tokens.push({
              type: "xref",
              text: longWord,
              target: `${path}->${methodPart}`,
            });
            i = k;
            continue;
          }
        }

        if (classPart.split(".").some((s) => /^[A-Z]/.test(s))) {
          const classPath = javaRefToPath(classPart);
          tokens.push({
            type: "xref",
            text: longWord,
            target: `${classPath}->${methodPart}`,
          });
          i = k; // leave '(' to be processed normally
          continue;
        }

        // Variable-receiver case: resolve `varName.method(...)` to a
        // class path. Only fires for single-identifier receivers
        // (no dots) — chained calls like `helper.someField.x(...)`
        // can't be type-resolved without proper field-type tracking.
        //
        // Resolution order (first hit wins):
        //   1. importMap (per-doc) — authoritative when the file
        //      explicitly imports the class.
        //   2. current class — `wfg.foo()` inside wfg.java is a self
        //      reference; resolve to the class being viewed.
        //   3. same-package — package-qualified classIndex hit. A package
        //      can't reuse a simple name, so this is collision-free.
        //   4. classIndex (project-wide) — last-writer-wins fallback.
        //
        // Steps 2–3 are the fix for the "wrong class on wfg.bihvbhi(...)"
        // jump: same-package / self references emit no `import`, so they
        // used to fall straight to step 4 and could resolve to a
        // same-named class in another package (common in obfuscated APKs).
        if (!classPart.includes(".")) {
          const recv = classPart.toLowerCase();
          let resolved: string | undefined = importMap?.get(classPart);
          if (!resolved && currentClass) {
            const slashIdx = currentClass.lastIndexOf("/");
            const currentSimple = (
              slashIdx === -1 ? currentClass : currentClass.slice(slashIdx + 1)
            ).toLowerCase();
            if (recv === currentSimple) {
              resolved = currentClass;
            } else if (slashIdx !== -1) {
              const pkgLower = currentClass.slice(0, slashIdx).toLowerCase();
              resolved = classIndex?.get(pkgLower + "/" + recv);
            }
          }
          if (!resolved) resolved = classIndex?.get(classPart);
          if (resolved) {
            tokens.push({
              type: "xref",
              text: longWord,
              target: `${resolved}->${methodPart}`,
            });
            i = k;
            continue;
          }
        }

        // Variable receiver we can't resolve (e.g. str2.getBytes) —
        // reset to just the base word and fall through to the plain
        // identifier path below.
        longWord = word;
        k = j;
      }

      // If contains uppercase segments (likely a class name in a dotted path)
      const segments = longWord.split(".");
      const hasUpperSegment = segments.some((s) => /^[A-Z]/.test(s));

      if (longWord.length > word.length && hasUpperSegment) {
        // It's a dotted class reference → xref (use $ for inner classes, / for packages)
        tokens.push({
          type: "xref",
          text: longWord,
          target: javaRefToPath(longWord),
        });
        i = k;
        continue;
      }

      if (JAVA_KEYWORDS.has(word)) {
        tokens.push({ type: "keyword", text: word });
      } else if (/^[A-Z]/.test(word)) {
        // Capitalized → likely a class/type name
        tokens.push({ type: "type", text: word });
      } else {
        tokens.push({ type: "plain", text: word });
      }
      i = j;
      continue;
    }

    // Punctuation / operator: plain
    tokens.push({ type: "plain", text: line[i] });
    i++;
  }

  return { tokens, multilineCommentOpen: false };
}

// ─── XML tokenizer ───────────────────────────────────────────────────────────

export function tokenizeXmlLine(line: string): TokenizedLine {
  const tokens: Token[] = [];
  let i = 0;

  while (i < line.length) {
    // Comment
    if (line.slice(i, i + 4) === "<!--") {
      const end = line.indexOf("-->", i + 4);
      if (end === -1) {
        tokens.push({ type: "comment", text: line.slice(i) });
        return tokens;
      }
      tokens.push({ type: "comment", text: line.slice(i, end + 3) });
      i = end + 3;
      continue;
    }

    // String value
    if (line[i] === '"') {
      let j = i + 1;
      while (j < line.length && line[j] !== '"') j++;
      const value = line.slice(i, j + 1);
      // Check if it looks like a class name (e.g., android:name="com.example.Foo")
      const inner = value.slice(1, -1);
      if (/^[a-z][a-z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)+$/.test(inner)) {
        tokens.push({ type: "plain", text: '"' });
        tokens.push({ type: "xref", text: inner, target: inner.replace(/\./g, "/") });
        tokens.push({ type: "plain", text: '"' });
      } else {
        tokens.push({ type: "string", text: value });
      }
      i = j + 1;
      continue;
    }

    // Tag name or attribute name
    if (/[a-zA-Z_:]/.test(line[i])) {
      let j = i;
      while (j < line.length && /[a-zA-Z0-9_:\-.]/.test(line[j])) j++;
      const word = line.slice(i, j);
      if (word.startsWith("android:") || word.startsWith("app:") || word.startsWith("tools:")) {
        tokens.push({ type: "keyword", text: word });
      } else if (/^[A-Z]/.test(word)) {
        tokens.push({ type: "type", text: word });
      } else {
        tokens.push({ type: "plain", text: word });
      }
      i = j;
      continue;
    }

    tokens.push({ type: "plain", text: line[i] });
    i++;
  }

  return tokens;
}

// ─── Main tokenizer entry point ───────────────────────────────────────────────

export function tokenizeCode(
  code: string,
  language: "smali" | "java" | "xml" | "text",
  /** Normalised current class path (`com/foo/Bar`, no `L`/`;`). Threaded
   *  through to the Java tokenizer so `this.method(` patterns can be
   *  promoted to xrefs that target this class. Smali/XML/text ignore it. */
  currentClass?: string,
  /** Project-wide lookup for variable receivers. Used as a fallback
   *  when no explicit import in the active doc resolves the
   *  receiver. Java-only; smali/xml/text ignore it. */
  classIndex?: ClassIndex,
  /** Per-doc import map — authoritative for variable-receiver
   *  resolution. Built once per render via [`buildImportMap`] on the
   *  same `code`. Java-only. */
  importMap?: ImportMap,
  /** Set of all known fully-qualified class paths (slash form). Lets the
   *  Java tokenizer resolve all-lowercase fully-qualified method calls
   *  (`hivhi.wfg.bihvbhi(...)`). Java-only. */
  classPaths?: Set<string>,
): TokenizedLine[] {
  const lines = code.split("\n");
  const result: TokenizedLine[] = [];

  if (language === "smali") {
    for (const line of lines) {
      result.push(tokenizeSmaliLine(line));
    }
  } else if (language === "java") {
    let multilineOpen = false;
    for (const line of lines) {
      const { tokens, multilineCommentOpen } = tokenizeJavaLine(
        line,
        multilineOpen,
        currentClass,
        classIndex,
        importMap,
        classPaths,
      );
      multilineOpen = multilineCommentOpen;
      result.push(tokens);
    }
  } else if (language === "xml") {
    for (const line of lines) {
      result.push(tokenizeXmlLine(line));
    }
  } else {
    // Plain text — no tokenization, each line is a single plain token
    for (const line of lines) {
      result.push([{ type: "plain", text: line }]);
    }
  }

  return result;
}
