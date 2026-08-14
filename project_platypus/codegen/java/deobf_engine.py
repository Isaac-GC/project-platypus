import unicodedata
from dataclasses import dataclass

from codegen.java.analysis import AnalysisConfig
from codegen.java.z_algorithm import DeadCodeDetector
from dex.helpers import sign_extend


@dataclass
class DeobfuscationChange:
    kind:      str
    codepoint: int
    before:    str
    after:     str

    def __str__(self):
        return f"[{self.kind}] @{self.codepoint:#x}: {self.before} -> {self.after}]"


@dataclass
class FoldedInstruction:
    original:   object
    result_reg: int
    result_val: int

    @property
    def opcode(self): return 0x14 # treat as a const

    @property
    def codepoint(self): return self.original.codepoint

    @property
    def vA(self): return self.result_reg

    @property
    def vB(self): return self.result_val

    @property
    def vC(self): return None

    @property
    def nop_data(self): return {} # NOPE, not gonna return anything, lol

    @property
    def instruction_str(self): return f"const v{self.result_reg}, {self.result_val} /* folded */"



class DeobfuscationEngine:
    # Level 1 -> "safe" (constant-folding, trivial dead code)
    # Level 2 (default) -> "aggressive" (string decryption, simplify control flow)
    # Level 3 -> "speculative" (heuristic pattern matching, may change semantics, probably will break things fyi)

    def __init__(self, method, cfg, config: AnalysisConfig):
        self.method = method
        self.cfg = cfg
        self.config = config
        self.changes = []


    # TODO: Simplify this?
    def apply(self):
        instrs = list(self.method.instructions)
        level  = self.config.deobfuscation_level

        # always do level 1 stuffs
        instrs = self._fold_constants(instrs)
        instrs = self._simplify_goto_chains(instrs)
        instrs = self._remove_nop_padding(instrs)

        if level >= 2:
            instrs = self._decrypt_xor_strings(instrs)
            instrs = self._simplify_constants(instrs)
            instrs = self._inline_single_use_consts(instrs)

        if level >= 3:
            instrs = self.heuristic_rename(instrs)
            instrs = self._collapse_move_chains(instrs)

        return instrs


    def _fold_constants(self, instrs):
        const_vals = {}
        result = []
        for instr in instrs:
            op = instr.opcode

            if op in (0x12, 0x13, 0x14) and instr.vA is not None:
                const_vals[instr.vA] = instr.vB
                result.append(instr)

            elif 0x90 <= op <= 0x9a: # binary int ops
                vB_val = const_vals.get(instr.vB)
                vC_val = const_vals.get(instr.vC)

                if vB_val is not None and vC_val is not None:
                    folded = self._eval_binary(op, vB_val, vC_val)
                    if folded is not None:
                        fake_instr = FoldedInstruction(instr, instr.vA, folded)
                        const_vals[instr.vA] = folded
                        result.append(fake_instr)
                        self.changes.append(
                            DeobfuscationChange(
                                kind = 'constant_fold',
                                codepoint = instr.codepoint,
                                before = instr.instruction_str,
                                after = f"const v{instr.vA}, {folded}"
                            ))
                        continue
                result.append(instr)

            else:
                # write to vA - invalidate constant
                if instr.vA is not None and instr.vA in const_vals:
                    del const_vals[instr.vA]
                result.append(instr)

        return result


    def _simplify_goto_chains(self, instrs):
        codepoint_to_idx = { instr.codepoint: i for i, instr in enumerate(instrs) }
        result = list(instrs)

        for i, instr in enumerate(result):
            if instr.opcode not in (0x28, 0x29, 0x2a):
                continue

            bits = {0x28: 8, 0x29: 16, 0x2a: 32}[instr.opcode]
            target = instr.codepoint + sign_extend(instr.vA, bits)
            hops = 0

            while hops < 10:
                target_idx = codepoint_to_idx.get(target)
                if target_idx is None:
                    break

                target_instr = result[target_idx]
                if target_instr.opcode not in (0x28, 0x29, 0x2a):
                    break

                bits2 = {0x28: 8, 0x29: 16, 0x2a: 32}[target_instr.opcode]
                new_target = target_instr.codepoint + sign_extend(target_instr.vA, bits2)
                if new_target == target:
                    break

                target = new_target
                hops += 1

            if hops > 0:
                self.changes.append(
                    DeobfuscationChange(
                        kind = 'goto_chain',
                        codepoint = instr.codepoint,
                        before = instr.instruction_str,
                        after = f"goto :resolved_{target:x} /* chain depth {hops} */"
                    ))

        return result


    def _remove_nop_padding(self, instrs):
        result = []
        nop_run = 0

        for instr in instrs:
            if instr.opcode == 0x00 and not instr.nop_data:
                nop_run += 1
                if nop_run <= 1:
                    result.append(instr)
                else:
                    self.changes.append(
                        DeobfuscationChange(
                            kind = "nop_removal",
                            codepoint = instr.codepoint,
                            before = "nop",
                            after = "/* removed nop padding */"
                        ))

            else:
                nop_run = 0
                result.append(instr)

        return result


    def _decrypt_xor_strings(self, instrs):
        result = list(instrs)
        i = 0
        encrypted_strings = {}

        while i < len(result):
            instr = result[i]

            if instr.opcode in (0x1a, 0x1b):
                try:
                    raw = self.method.dex.dex.string_ids[instr.vB].value.raw_data
                    s   = raw.decode('utf-8', errors='replace') if isinstance(raw, bytes) else str(raw)
                    encrypted_strings[instr.vA] = s
                except (IndexError, AttributeError):
                    pass

            # look for the xor loop
            if instr.opcode == 0xd7: # xor-int/lit8
                src_str = encrypted_strings.get(instr.vB)
                if src_str:
                    key = instr.vC & 0xFF
                    try:
                        decrypted = ''.join(chr(ord(c) ^ key) for c in src_str)
                        if self._is_printable(decrypted):
                            self.changes.append(
                                DeobfuscationChange(
                                    kind = 'xor_decrypt',
                                    codepoint = instr.codepoint,
                                    before = f'xor-encrypted: "{src_str}"',
                                    after = f"decrypted: '{decrypted}'"
                            ))
                    except (ValueError, OverflowError):
                        pass

            i += 1

        return result


    def _simplify_constant_branches(self, instrs):
        const_vals = {}
        result = []

        for instr in instrs:
            op = instr.opcode

            if op in (0x12, 0x13, 0x14) and instr.vA is not None:
                const_vals[instr.vA] = instr.vB

            elif 0x38 <= op <= 0x3d:
                val = const_vals.get(instr.vA)
                if val is not None:
                    taken = DeadCodeDetector._eval_ifz(op, val)
                    self.changes.append(
                        DeobfuscationChange(
                            kind = 'constant_branch',
                            codepoint = instr.codepoint,
                            before = instr.instruction_str,
                            after = f"/* always {'taken' if taken else 'not taken'} */"
                    ))

            elif 0x32 <= op <= 0x37:
                vA = const_vals.get(instr.vA)
                vB = const_vals.get(instr.vB)

                if vA is not None and vB is not None:
                    taken = DeadCodeDetector._eval_if(op, vA, vB)
                    self.changes.append(
                        DeadCodeDetector(
                            kind = 'constant_branch',
                            codepoint = instr.codepoint,
                            before = instr.instruction_str,
                            after = f"/* always {'taken' if taken else 'not taken'} */"
                    ))


            if instr.vA is not None:
                const_vals.pop(instr.vA, None)

            result.append(instr)

        return result

    def _inline_single_use_consts(self, instrs):
        use_count = {}
        def_instr = {}

        for i, instr in enumerate(instrs):
            for reg in (instr.vB, instr.vC, instr.vD, instr.vE, instr.vF, instr.vG):
                if reg is not None:
                    use_count[reg] = use_count.get(reg, 0) + 1

                if instr.vA is not None and instr.opcode in (0x12, 0x13, 0x14):
                    def_instr[instr.vA] = i

        # mark any single-use constants
        for reg, count in use_count.items():
            if count == 1 and reg in def_instr:
                def_idx = def_instr[reg]
                self.changes.append(
                    DeobfuscationChange(
                        kind = 'inline_const',
                        codepoint = instrs[def_idx].codepoint,
                        before = instrs[def_idx].instruction_str,
                        after = f"/* inlined into use site */"
                ))

        return instrs


    def _heuristic_rename(self, instrs):
        RENAME_HINTS = { # just a shortlist -> TODO: Increase list or do this a smarter way
            'Ljava/lang/String;->length': 'strLen',
            'Ljava/lang/String;->charAt': 'strChar',
            'Ljava/util/List;->size':     'listSize',
            'Ljava/util/Map;->get':       'mapVal',
            'Landroid/content/Context;':  'ctx',
            'Landroid/app/Activity;':     'activity',
        }

        for instr in instrs:
            if instr.opcode in (0x6e, 0x6f, 0x70, 0x71, 0x72):
                ref = instr.instruction_str
                for pattern, hint in RENAME_HINTS.items():
                    if pattern in ref:
                        self.changes.append(DeobfuscationChange(
                            kind = 'rename_hint',
                            codepoint = instr.codepoint,
                            before = ref,
                            after = f"/* result likely: {hint} */"
                        ))

        return instrs

    def _collapse_move_chains(self, instrs):
        move_source = {}
        result = []

        for instr in instrs:
            op = instr.opcode
            if 0x01 <= op <= 0x09:
                if instr.vA is not None and instr.vB is not None:
                    # trace to original source
                    src = instr.vB
                    while src in move_source:
                        src = move_source[src]

                    if src != instr.vB:
                        self.changes.append(
                            DeobfuscationChange(
                                kind = 'move_chain',
                                codepoint = instr.codepoint,
                                before = instr.instruction_str,
                                after = f"move v{instr.vA}, v{src} /* chain collapsed */"
                        ))
                        move_source[src] = src

            else:
                if instr.vA is not None:
                    move_source.pop(instr.vA, None)
                result.append(instr)

        return result

    def _eval_bianry(self, op, a, b):
        try:
            return {
                0x90: a + b,
                0x91: a - b,
                0x92: a * b,
                0x93: a // b if b != 0 else None,
                0x94: a % b if b != 0 else None,
                0x95: a & b,
                0x96: a | b,
                0x97: a ^ b,
                0x98: a << (b & 31),
                0x99: a >> (b & 31),
                0x9a: (a % (1 << 32)) >> (b & 31),
            }.get(op)
        except (OverflowError, ValueError):
            return None

    def _is_printable(self, s):
        return all(unicodedata.category(c)[0] != 'C' or c in '\n\t\r' for c in s)