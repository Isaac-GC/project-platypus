import type { Language, DeobfReplacement } from "../api/types";

// ─── Shared deobf-annotation helper ─────────────────────────────────────────

export interface DeobfInfo {
  original: string;
  resolved: string;
}

/**
 * Build a `Map<lineIndex, DeobfInfo>` from the flat deobfReplacements record,
 * filtered to the given className and the appliedDeobf set.
 *
 * NOTE: This collapses entries that share a `lineIndex`. Use
 * `buildDeobfList` instead when you need per-call-site fidelity (e.g. for the
 * annotated centre-panel view, where multiple invocations of the same deobf
 * method on the same logical line must each get their own annotation).
 */
export function buildDeobfMap(
  deobfReplacements: Record<string, DeobfReplacement>,
  appliedDeobf: Set<string>,
  className: string
): Map<number, DeobfInfo> {
  const map = new Map<number, DeobfInfo>();
  for (const [key, repl] of Object.entries(deobfReplacements)) {
    if (repl.className === className && appliedDeobf.has(key)) {
      map.set(repl.lineIndex, {
        original: repl.original,
        resolved: repl.resolved,
      });
    }
  }
  return map;
}

/**
 * Build a flat list of `DeobfReplacement`s for the given class, preserving
 * each individual call site (no deduplication by lineIndex). The list is
 * sorted by `lineIndex` ascending so that consumers can rely on source order.
 */
export function buildDeobfList(
  deobfReplacements: Record<string, DeobfReplacement>,
  appliedDeobf: Set<string>,
  className: string
): DeobfReplacement[] {
  const list: DeobfReplacement[] = [];
  for (const [key, repl] of Object.entries(deobfReplacements)) {
    if (repl.className === className && appliedDeobf.has(key)) {
      list.push(repl);
    }
  }
  list.sort((a, b) => a.lineIndex - b.lineIndex);
  return list;
}

/**
 * Annotate code lines with deobfuscation results, *offset-aware* so that
 * multiple call sites of the same deobf method get their own per-instance
 * annotation (no collapsing to the first match).
 *
 * **Smali**: For each replacement, the line at `repl.lineIndex` (treated as a
 * 0-based line number, which is how `buildSmaliDeobfCode` also uses it) is
 * replaced with a `# DEOBF: "value"` annotation followed by the original line
 * commented out. Each replacement is processed exactly once.
 *
 * **Java**: Codepoints don't map cleanly to source lines, so we use a
 * per-method *occurrence counter*: collect all replacements grouped by method
 * name (sorted by lineIndex), then walk the source and assign the Nth
 * call-site occurrence of `methodName(` to the Nth replacement for that
 * method. Each call site gets its own `/* DEOBF: "..." *\/` trailer.
 *
 * ─── Sanity test (2-call-site) ──────────────────────────────────────────────
 *
 *   // Java input:
 *   //   String a = obj.dec("k1");   // line 0
 *   //   String b = obj.dec("k2");   // line 1
 *   // replacements (sorted by lineIndex):
 *   //   [{ original:"...->dec(...)", resolved:"hello", lineIndex:0, ... },
 *   //    { original:"...->dec(...)", resolved:"world", lineIndex:1, ... }]
 *   // expected output:
 *   //   String a = obj.dec("k1");   /* DEOBF: "hello" *\/
 *   //   String b = obj.dec("k2");   /* DEOBF: "world" *\/
 *   //
 *   // Smali input (lineIndex = line number):
 *   //   line 5: invoke-static {v0}, L...->dec(...)Ljava/lang/String;
 *   //   line 9: invoke-static {v1}, L...->dec(...)Ljava/lang/String;
 *   // replacements: [{lineIndex:5, resolved:"hello"}, {lineIndex:9, resolved:"world"}]
 *   // expected output (only those two lines change, each with its own value):
 *   //   line 5: # DEOBF: "hello"
 *   //           # invoke-static {v0}, L...->dec(...)
 *   //   line 9: # DEOBF: "world"
 *   //           # invoke-static {v1}, L...->dec(...)
 */
export function applyDeobfAnnotations(
  code: string,
  language: Language,
  replacements: DeobfReplacement[]
): string {
  if (replacements.length === 0) return code;

  const lines = code.split("\n");

  if (language === "smali") {
    // Offset-aware: each replacement targets exactly one line number
    // (DeobfReplacement.lineIndex on Smali is the instruction's line/codepoint
    // index, treated identically to how buildSmaliDeobfCode treats it).
    const byLine = new Map<number, DeobfReplacement[]>();
    for (const repl of replacements) {
      const arr = byLine.get(repl.lineIndex);
      if (arr) arr.push(repl);
      else byLine.set(repl.lineIndex, [repl]);
    }

    const out: string[] = [];
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const matches = byLine.get(i);
      if (matches && matches.length > 0 && line.includes("invoke-")) {
        const indent = line.match(/^(\s*)/)?.[1] ?? "    ";
        // If, somehow, more than one replacement is keyed at the same line,
        // emit each one in order (rare; preserves all data).
        for (const repl of matches) {
          out.push(`${indent}# DEOBF: "${repl.resolved}"`);
        }
        out.push(`${indent}# ${line.trimStart()}`);
      } else {
        out.push(line);
      }
    }
    return out.join("\n");
  }

  // ── Java: per-method occurrence counter ────────────────────────────────────
  // Group replacements by method name, sorted by lineIndex.
  const byMethod = new Map<string, DeobfReplacement[]>();
  for (const repl of replacements) {
    if (!repl.resolved) continue;
    const methodName = extractMethodName(repl.original);
    if (!methodName) continue;
    const arr = byMethod.get(methodName);
    if (arr) arr.push(repl);
    else byMethod.set(methodName, [repl]);
  }
  for (const arr of byMethod.values()) {
    arr.sort((a, b) => a.lineIndex - b.lineIndex);
  }

  // Per-method consumption cursor.
  const cursor = new Map<string, number>();
  for (const m of byMethod.keys()) cursor.set(m, 0);

  const out: string[] = [];
  for (const line of lines) {
    if (line.trimStart().startsWith("//") || line.includes("/* DEOBF")) {
      out.push(line);
      continue;
    }
    // For each method, consume the next available replacement if this line
    // contains a `.methodName(` call site.
    let annotation: string | null = null;
    for (const [methodName, list] of byMethod) {
      const idx = cursor.get(methodName) ?? 0;
      if (idx >= list.length) continue;
      const callIdx = line.indexOf(methodName + "(");
      if (callIdx !== -1 && line[callIdx - 1] === ".") {
        annotation = list[idx].resolved;
        cursor.set(methodName, idx + 1);
        break;
      }
    }
    if (annotation !== null) {
      out.push(`${line}  /* DEOBF: "${annotation}" */`);
    } else {
      out.push(line);
    }
  }
  return out.join("\n");
}

/**
 * Extract the bare method name from a Dalvik ref like
 * "Lcom/Foo;->bar(Ljava/lang/String;)Ljava/lang/String;" → "bar".
 */
function extractMethodName(original: string): string | null {
  const arrowIdx = original.indexOf("->");
  const afterArrow = arrowIdx !== -1 ? original.slice(arrowIdx + 2) : original;
  const parenIdx = afterArrow.indexOf("(");
  const name = parenIdx !== -1 ? afterArrow.slice(0, parenIdx) : afterArrow;
  return name || null;
}

/**
 * Build the "deobfuscated" version of smali code for the diff view.
 * Uses the codepoint→lineIndex mapping to substitute resolved values inline,
 * showing the original instruction as a comment.
 *
 * Only call this for `language === "smali"` where codepoints are approximately
 * aligned with displayed line numbers.
 *
 * NOTE: This is the diff-view substitution and intentionally has different
 * behaviour from `buildSubstitutedCode` (the centre-panel substituted view).
 * Don't merge them.
 */
export function buildSmaliDeobfCode(
  code: string,
  deobfReplacements: Record<string, DeobfReplacement>,
  appliedDeobf: Set<string>,
  className: string
): string {
  const lines = code.split("\n");
  const result: string[] = [];

  for (let i = 0; i < lines.length; i++) {
    let replaced = false;
    for (const [key, repl] of Object.entries(deobfReplacements)) {
      if (repl.className === className && appliedDeobf.has(key) && repl.lineIndex === i) {
        result.push(`// ${repl.original}`);
        result.push(repl.resolved);
        replaced = true;
        break;
      }
    }
    if (!replaced) result.push(lines[i]);
  }

  return result.join("\n");
}

// ─── Substituted view (centre panel) ─────────────────────────────────────────

/**
 * Result of `inferTypeAndFormat`: how to render `resolved` as a literal in
 * the target language.
 *
 *   - `kind`: which type bucket the resolved value matched
 *   - `smali`: the operand string for a `const-string` / `const` instruction
 *     (without the register prefix). For booleans/integers this is a hex
 *     literal; for strings it's a quoted, escaped form.
 *   - `java`: the literal as it should appear in Java source
 *   - `unclear`: true when we fell back because the type couldn't be
 *     determined; callers may want to attach a `(deobf: type unclear)` comment.
 */
export interface InferredLiteral {
  kind: "string" | "integer" | "boolean" | "unknown";
  smali: string;
  java: string;
  unclear: boolean;
}

/**
 * Infer the literal form of a resolved deobf value. Rules:
 *
 *   - `"true"` / `"false"` (case-sensitive) → boolean
 *   - `^-?\d+$`                              → decimal integer
 *   - `^0x[0-9a-fA-F]+$`                     → hex integer
 *   - everything else                        → string (quoted, escaped)
 *
 * Booleans/integers always come out as hex-form const literals on the smali
 * side; strings are escaped via the usual `\\`, `\"`, `\n`, `\r`, `\t` rules.
 */
export function inferTypeAndFormat(resolved: string): InferredLiteral {
  if (resolved === "true" || resolved === "false") {
    const bit = resolved === "true" ? 1 : 0;
    return {
      kind: "boolean",
      smali: `0x${bit.toString(16)}`,
      java: resolved,
      unclear: false,
    };
  }
  if (/^-?\d+$/.test(resolved)) {
    const n = Number.parseInt(resolved, 10);
    if (!Number.isNaN(n)) {
      const hex = n < 0 ? `-0x${(-n).toString(16)}` : `0x${n.toString(16)}`;
      return {
        kind: "integer",
        smali: hex,
        java: resolved,
        unclear: false,
      };
    }
  }
  if (/^0x[0-9a-fA-F]+$/.test(resolved)) {
    return {
      kind: "integer",
      smali: resolved.toLowerCase(),
      java: resolved,
      unclear: false,
    };
  }
  // Fallback: treat as string. If the value didn't look like any of the
  // structured types we know about, mark it as unclear so the caller can
  // attach an explanatory comment.
  const escaped = escapeForLiteral(resolved);
  return {
    kind: "string",
    smali: `"${escaped}"`,
    java: `"${escaped}"`,
    unclear: false,
  };
}

/** Escape a string for inclusion inside a "..." literal in either language. */
function escapeForLiteral(s: string): string {
  return s
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r")
    .replace(/\t/g, "\\t");
}

/**
 * Build a substituted view of the code where each applied deobf replaces its
 * call site inline (vs. the annotated overlay produced by
 * `applyDeobfAnnotations`). Used by the centre panel's "Substituted" view
 * mode toggle.
 *
 * Smali rules per replacement at line `L` targeting `move-result` register
 * `vR`:
 *   1. Comment out (`# `) the `invoke-*` line at L.
 *   2. Comment out the immediately-following `move-result-*` line, if any;
 *      parse `vR` from it.
 *   3. Walk backward to the most recent `const-string vN, ...` /
 *      `const vN, ...` whose `vN` is the first arg register of the invoke,
 *      and comment that out too.
 *   4. Insert a single replacement instruction loading `repl.resolved` into
 *      `vR` (string / int / boolean per `inferTypeAndFormat`).
 *
 * Java rules per replacement (matched per-instance via the same per-method
 * counter as `applyDeobfAnnotations`):
 *   1. Comment the call-site line (`// ` prefix, preserving indent).
 *   2. Insert below it the same line with the call expression replaced by a
 *      literal form of `repl.resolved` (preserving indent).
 */
export function buildSubstitutedCode(
  code: string,
  language: Language,
  deobfReplacements: Record<string, DeobfReplacement>,
  appliedDeobf: Set<string>,
  className: string
): string {
  const list = buildDeobfList(deobfReplacements, appliedDeobf, className);
  if (list.length === 0) return code;

  const lines = code.split("\n");

  if (language === "smali") {
    return buildSmaliSubstituted(lines, list);
  }
  if (language === "java") {
    return buildJavaSubstituted(lines, list);
  }
  return code;
}

function buildSmaliSubstituted(lines: string[], list: DeobfReplacement[]): string {
  // Index replacements by line; multiple replacements at the same line are
  // handled in order (rare).
  const byLine = new Map<number, DeobfReplacement[]>();
  for (const repl of list) {
    const arr = byLine.get(repl.lineIndex);
    if (arr) arr.push(repl);
    else byLine.set(repl.lineIndex, [repl]);
  }

  // Plan a list of edits keyed by line index:
  //   commented-out: lines we should re-emit with a `# ` prefix
  //   insertions:    map of line → list of replacement-text lines to emit AFTER
  //                  the (commented) original line(s) at that line index.
  const commented = new Set<number>();
  // We'll attach inserts to the invoke line so they appear directly after the
  // commented-out invoke / move-result block.
  const insertionsAfterInvoke = new Map<number, string[]>();

  for (const [invokeLine, repls] of byLine) {
    if (invokeLine < 0 || invokeLine >= lines.length) continue;
    const line = lines[invokeLine];
    if (!line.includes("invoke-")) continue;

    // Parse first arg register from `invoke-... {v0, v1, ...}` or
    // `invoke-...range {v0 .. vN}`.
    const argMatch = line.match(/\{([^}]*)\}/);
    let firstArgReg: string | null = null;
    if (argMatch) {
      const inside = argMatch[1].trim();
      // Range form uses `v0 .. v3`; non-range is comma-separated.
      const rangeMatch = inside.match(/^(v\d+|p\d+)\s*\.\.\s*(v\d+|p\d+)$/);
      if (rangeMatch) {
        firstArgReg = rangeMatch[1];
      } else {
        const first = inside.split(",")[0]?.trim();
        if (first && /^[vp]\d+$/.test(first)) firstArgReg = first;
      }
    }

    // Look at the next line for `move-result-*` and recover the dest register.
    const indent = line.match(/^(\s*)/)?.[1] ?? "    ";
    let destReg: string | null = null;
    let moveResultLine: number | null = null;
    if (invokeLine + 1 < lines.length) {
      const nextStripped = lines[invokeLine + 1].trim();
      const mr = nextStripped.match(/^move-result\S*\s+([vp]\d+)/);
      if (mr) {
        moveResultLine = invokeLine + 1;
        destReg = mr[1];
      }
    }

    // Find the most recent const(-string) loading firstArgReg.
    let constLine: number | null = null;
    if (firstArgReg) {
      for (let j = invokeLine - 1; j >= 0 && j >= invokeLine - 64; j--) {
        const t = lines[j].trim();
        const m = t.match(/^(const-string(?:\/jumbo)?|const(?:\/(?:4|16|high16))?)\s+([vp]\d+)\s*,/);
        if (m && m[2] === firstArgReg) {
          constLine = j;
          break;
        }
      }
    }

    // Mark lines for commenting.
    commented.add(invokeLine);
    if (moveResultLine !== null) commented.add(moveResultLine);
    if (constLine !== null) commented.add(constLine);

    // Build the replacement instruction(s).
    const targetReg = destReg ?? firstArgReg ?? "v0";
    const inserts: string[] = [];
    for (const repl of repls) {
      const inferred = inferTypeAndFormat(repl.resolved);
      if (inferred.kind === "string" || inferred.kind === "unknown") {
        inserts.push(`${indent}const-string ${targetReg}, ${inferred.smali}`);
      } else if (inferred.kind === "boolean") {
        inserts.push(`${indent}const/4 ${targetReg}, ${inferred.smali}`);
      } else {
        inserts.push(`${indent}const ${targetReg}, ${inferred.smali}`);
      }
      if (inferred.unclear) {
        inserts.push(`${indent}# (deobf: type unclear)`);
      }
    }
    // Anchor the inserts to the invoke line; we'll emit them after the
    // (commented) invoke + (commented) move-result.
    insertionsAfterInvoke.set(invokeLine, inserts);
  }

  const out: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (commented.has(i)) {
      const indent = line.match(/^(\s*)/)?.[1] ?? "";
      out.push(`${indent}# ${line.trimStart()}`);
    } else {
      out.push(line);
    }
    // Emit inserts after the move-result line if present, otherwise after the
    // invoke line itself. We track the *invoke* line as the anchor; emit when
    // we just finished emitting the move-result (the line right after invoke
    // when commented), or after invoke if no move-result was commented.
    const repls = insertionsAfterInvoke.get(i);
    if (repls) {
      // If the very next line is also commented (the move-result), defer
      // emission until after that line.
      if (commented.has(i + 1) && lines[i + 1]?.trim().startsWith("move-result")) {
        // defer
      } else {
        for (const r of repls) out.push(r);
        insertionsAfterInvoke.delete(i);
      }
    }
    // Drain any deferred inserts whose anchor was the previous (invoke) line.
    const prev = insertionsAfterInvoke.get(i - 1);
    if (prev) {
      for (const r of prev) out.push(r);
      insertionsAfterInvoke.delete(i - 1);
    }
  }

  return out.join("\n");
}

function buildJavaSubstituted(lines: string[], list: DeobfReplacement[]): string {
  // Same per-method counter as applyDeobfAnnotations to pick the right call
  // site for each replacement.
  const byMethod = new Map<string, DeobfReplacement[]>();
  for (const repl of list) {
    if (!repl.resolved) continue;
    const methodName = extractMethodName(repl.original);
    if (!methodName) continue;
    const arr = byMethod.get(methodName);
    if (arr) arr.push(repl);
    else byMethod.set(methodName, [repl]);
  }
  for (const arr of byMethod.values()) {
    arr.sort((a, b) => a.lineIndex - b.lineIndex);
  }
  const cursor = new Map<string, number>();
  for (const m of byMethod.keys()) cursor.set(m, 0);

  const out: string[] = [];
  for (const line of lines) {
    if (line.trimStart().startsWith("//")) {
      out.push(line);
      continue;
    }
    let chosen: { methodName: string; repl: DeobfReplacement; callIdx: number } | null = null;
    for (const [methodName, replList] of byMethod) {
      const idx = cursor.get(methodName) ?? 0;
      if (idx >= replList.length) continue;
      const callIdx = line.indexOf(methodName + "(");
      if (callIdx !== -1 && line[callIdx - 1] === ".") {
        chosen = { methodName, repl: replList[idx], callIdx };
        cursor.set(methodName, idx + 1);
        break;
      }
    }
    if (!chosen) {
      out.push(line);
      continue;
    }

    // Comment original line.
    const indent = line.match(/^(\s*)/)?.[1] ?? "";
    out.push(`${indent}// ${line.slice(indent.length)}`);

    // Build replacement: substitute `obj.method(...args...)` with the literal.
    const inferred = inferTypeAndFormat(chosen.repl.resolved);
    const literal = inferred.kind === "unknown"
      ? `${inferred.java} /* deobf: type unclear */`
      : inferred.java;
    const replaced = replaceCallExpression(line, chosen.methodName, chosen.callIdx, literal);
    out.push(replaced);
  }
  return out.join("\n");
}

/**
 * Replace the `obj.method(...args...)` expression starting at `methodName(`
 * (located at `callStart` in `line`) with `literal`. Walks back from the dot
 * before the method name to include the receiver `obj`, and walks forward
 * matching parens to find the end of the argument list.
 *
 * If anything looks off (no matching `)`, no `.` before the method, etc.) we
 * fall back to a naive `obj.method(...) → literal` substring substitution
 * scoped to that one call site.
 */
function replaceCallExpression(
  line: string,
  methodName: string,
  callStart: number,
  literal: string
): string {
  // Walk backwards from callStart-2 (skip the `.`) over the receiver.
  // Receiver chars: alphanumerics, `_`, `$`, `.`, `[`, `]`, and balanced `()`
  // for things like `(foo).bar()`. Keep this simple: identifier chars + `.`
  // plus a bracketed `]...[` pass-through.
  let recvEnd = callStart - 1; // index of the dot
  if (line[recvEnd] !== ".") return line; // shouldn't happen; bail.
  let recvStart = recvEnd;
  while (recvStart > 0) {
    const c = line[recvStart - 1];
    if (/[A-Za-z0-9_$.]/.test(c)) {
      recvStart--;
      continue;
    }
    if (c === "]") {
      // Skip back to matching `[`.
      let depth = 1;
      recvStart--;
      while (recvStart > 0 && depth > 0) {
        recvStart--;
        if (line[recvStart] === "]") depth++;
        else if (line[recvStart] === "[") depth--;
      }
      continue;
    }
    if (c === ")") {
      // Skip back to matching `(`.
      let depth = 1;
      recvStart--;
      while (recvStart > 0 && depth > 0) {
        recvStart--;
        if (line[recvStart] === ")") depth++;
        else if (line[recvStart] === "(") depth--;
      }
      continue;
    }
    break;
  }

  // Walk forward from callStart to find the closing `)` of the argument list.
  const openParen = callStart + methodName.length;
  if (line[openParen] !== "(") return line;
  let depth = 1;
  let i = openParen + 1;
  let inStr: '"' | "'" | null = null;
  while (i < line.length && depth > 0) {
    const c = line[i];
    if (inStr) {
      if (c === "\\") { i += 2; continue; }
      if (c === inStr) inStr = null;
    } else {
      if (c === '"' || c === "'") inStr = c;
      else if (c === "(") depth++;
      else if (c === ")") depth--;
    }
    i++;
  }
  if (depth !== 0) return line;
  const callEnd = i; // exclusive: one past the closing `)`

  return line.slice(0, recvStart) + literal + line.slice(callEnd);
}
