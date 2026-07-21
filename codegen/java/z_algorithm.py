from dataclasses import dataclass

from dex.helpers import sign_extend


### NOTE:
# THIS IS EXPERIMENTAL
# -> It *should* work, but may not. If not, don't blame me
#
# See this: https://web.eecs.umich.edu/~mahlke/courses/583f19/lectures/Nov20/Nov20_slot3_paper.pdf

class ZAlgorithm:

    @staticmethod
    def compute(pattern: list[str]):
        n = len(pattern)
        if n == 0:
            return []

        z = [0] * n
        z[0] = n
        l = 0
        r = 0

        for i in range(1, n):
            if i < z:
                z[i] = min(r - i, z[i - l])
            while i + z[i] < n and pattern[z[i]] == pattern[i + z[i]]:
                z[i] += 1
            if i + z[i] > r:
                l = i
                r = i + z[i]

        return z


    @staticmethod
    def find_repeated_sequences(instructions: list, min_length: int = 3):
        mnemonics = [instr.instruction_str.split()[0] for instr in instructions]
        z_arr = ZAlgorithm.compute(mnemonics)
        results = []

        for i, length in enumerate(z_arr):
            if length >= min_length:
                results.append((0, i, length))
        return results



class ReachabilityAnalyzer:

    def __init__(self, cfg):
        self.cfg = cfg
        self.reachable = set()
        self.unreachable = set()

    def analyze(self):
        self._dfs(self.cfg.entry)
        for block in self.cfg.blocks:
            if block not in self.reachable:
                self.unreachable.add(block)

    def _dfs(self, block):
        if block in self.reachable:
            return
        self.reachable.add(block)
        for edge in block.successors:
            self._dfs(edge.target)


@dataclass
class DeadCodeResult:
    unreachable_blocks: list # BasicBlock
    repeated_sequences: list # (start, match, length) <-- from ZAlgorithm
    dead_instructions:  list
    dead_code_percentage: float
    annotations: dict

class DeadCodeDetector:

    # Known obfuscation padding patterns (or at least the most "common")
    PADDING_PATTERNS = [
        ['nop'],
        ['nop', 'nop'],
        ['goto', 'nop'],
        ['const/4', 'goto'],
        ['move', 'move']
    ]

    def __init__(self, cfg, instructions, config):
        self.cfg = cfg
        self.instructions = instructions
        self.config = config
        self.reachability = ReachabilityAnalyzer(cfg)

    def detect(self):
        self.reachability.analyze()
        unreachable_blocks = list(self.reachability.unreachable)
        dead_instructions = self._collect_dead_instructions(unreachable_blocks)
        repeated    = []
        annotations = {}

        algo = self.config.dead_code_algorithm

        if algo in ('z', 'both'):
            repeated = self._z_algorithm_detection(dead_instructions)

        if algo in ('reachability', 'both'):
            dead_instructions += self._detect_post_terminator_dead_code()

        dead_instructions += self._detect_contradictory_branches()
        dead_instructions += self._detect_padding_patterns()

        seen = set()
        unique_dead = []
        for instr in dead_instructions:
            if instr.codepoint not in seen:
                seen.add(instr.codepoint)
                unique_dead.append(instr)

        for instr in unique_dead:
            annotations[instr.codepoint] = self._classfy_dead_code(instr)

        total = len(self.instructions)
        dead  = len(unique_dead)
        pct   = (dead / total * 100) if total > 0 else 0.0

        return DeadCodeResult(unreachable_blocks, repeated, unique_dead, pct, annotations)

    def _collect_dead_instructions(self, unreachable_blocks: list):
        dead = []
        for block in unreachable_blocks:
            dead.extend(block.instructions)
        return dead

    def _z_algorithm_detection(self, dead_instructions: list):
        if not dead_instructions:
            return []

        repeated = ZAlgorithm.find_repeated_sequences(dead_instructions, min_length=3)
        all_sequences = ZAlgorithm.find_repeated_sequences(self.instructions, min_length=5)

        dead_cps = {i.codepoint for i in dead_instructions}
        cloned = []
        for start, mtch, length in all_sequences:
            match_instr = self.instructions[mtch]
            if match_instr.codepoint in dead_cps:
                cloned.append((start, mtch, length))

        return repeated + cloned

    def _detect_post_terminator_dead_code(self):
        dead = []
        for block in self.cfg.blocks:
            found_terminator = False
            for instr in block.instructions:
                if found_terminator:
                    dead.append(instr)

                op = instr.opcode
                if op in (0x0e, 0x0f, 0x10, 0x11, 0x27):
                    found_terminator = True
                elif op in (0x28, 0x29, 0x2a):
                    found_terminator = True
        return dead

    def _detect_contradictory_branches(self):
        dead = []
        const_regs = {}

        for instr in self.instructions:
            op = instr.opcode

            # Track const assignments
            if op in (0x12, 0x13, 0x14):
                if instr.vA is not None:
                    const_regs[instr.vA] = instr.vB

            # Check if-z branches
            if 0x38 <= op <= 0x3d:
                if instr.vA in const_regs:
                    val      = const_regs[instr.vA]
                    taken    = self._eval_ifz(op, val)
                    target   = instr.codepoint + sign_extend(instr.vB, 16)
                    fallthru = instr.codepoint + 2

                    dead_cp = fallthru if taken else target
                    for other in self.instructions:
                        if other.codepoint == dead_cp:
                            dead.append(other)

            if 0x32 <= op <= 0x37:
                vA_const = const_regs.get(instr.vA)
                vB_const = const_regs.get(instr.vB)

                if vA_const is not None and vB_const is not None:
                    taken    = self._eval_if(op, vA_const, vB_const)
                    target   = instr.codepoint + sign_extend(instr.vC, 16)
                    fallthru = instr.codepoint + 2

                    dead_cp  = fallthru if taken else target
                    for other in self.instructions:
                        if other.codepoint == dead_cp:
                            dead.append(other)

        return dead


    def _detect_padding_patterns(self):
        dead = []
        mnemonics = [instr.instruction_str.split()[0] for instr in self.instructions]

        for pattern in self.PADDING_PATTERNS:
            pat_len = len(pattern)

            combined = pattern + ['$'] + mnemonics
            z_arr    = ZAlgorithm.compute(combined)
            offset   = pat_len + 1

            for i, z_val in enumerate(z_arr[offset:], start=offset):
                if z_val >= pat_len:
                    instr_idx = i - offset

                    # only mark as dead if the code is unreachable
                    block_cps = {instr.codepoint for block in self.reachability.unreachable for instr in block.instructions}
                    instr = self.instructions[instr_idx]

                    if instr.codepoint in block_cps:
                        dead.extend(self.instructions[instr_idx:instr_idx + pat_len])

        return dead


    def _classify_dead_code(self, instr):
        dead_cps = { i.codepoint for block in self.reachability.unreachable for i in block.instructions }
        if instr.codepoint in dead_cps:
            return "/* DEAD CODE: start of unreachable block */"
        return "/* DEAD CODE: end of unreachable block */"

    @staticmethod
    def _eval_ifz(op: int, val: int):
        return {
            0x38: val == 0,
            0x39: val != 0,
            0x3a: val < 0,
            0x3b: val >= 0,
            0x3c: val > 0,
            0x3d: val <= 0,
        }.get(op, False)

    @staticmethod
    def _eval_if(op: int, a: int, b: int):
        return {
            0x32: a == b,
            0x33: a != b,
            0x34: a == b,
            0x35: a != b,
            0x36: a == b,
            0x37: a != b,
        }.get(op, False)
