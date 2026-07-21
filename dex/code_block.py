import enum
import logging
from dataclasses import dataclass
from typing import Optional

from dex.helpers import sign_extend
from dex.instructions_new import InstructionBase
from vm.utils import LogHandler

handler = LogHandler()
log = logging.getLogger(__name__)
log.addHandler(handler)
log.setLevel(logging.DEBUG)

class BasicBlockType(enum.Enum):
    RETURN  = 0
    THROW   = 1
    GOTO    = 2
    IF      = 3
    SWITCH  = 4
    GENERIC = 5

class EdgeKind(enum.Enum):
    FALL_THROUGH = 0
    JUMP         = 1
    EXCEPTION    = 2
    SWITCH       = 3

class CFGEdge:
    def __init__(self,
                 source: 'BasicBlock',
                 target: 'BasicBlock',
                 kind: EdgeKind,
                 switch_key: Optional[int] = None):

        self.source = source
        self.target = target
        self.kind   = kind
        self.switch_key = switch_key


class BasicBlock:
    id: int

    def __init__(self):
        # For the VM
        self.instructions: list = []
        self.next_branch: Optional[int] = None # (If it branches off)
        self.block_type: BasicBlockType = BasicBlockType.GENERIC
        self.instr_idx_start = 0

        # CFG
        self.id = 0
        self.successors:   list[CFGEdge] = []
        self.predecessors: list[CFGEdge] = []

        # Dominator fields
        self.dominator: Optional['BasicBlock'] = None
        self.dom_children: list = []
        self.dom_frontier: list = []

        self.loop_header: bool      = False
        self.loop: Optional[object] = None
        self.ssa_defs: dict         = {}

    @property
    def first_codepoint(self) -> int:
        return self.instructions[0].codepoint if self.instructions else -1

    @property
    def last_instruction(self) -> int:
        return self.instructions[-1] if self.instructions else None

    def add_successor(self, target: 'BasicBlock', kind: EdgeKind, switch_key: Optional[int] = None):
        edge = CFGEdge(self, target, kind, switch_key)
        self.successors.append(edge)
        target.predecessors.append(edge)

class CodeBlock:
    """
        This implementation of code block is not synonymous with the documentation. Instead, it
        intends to put most of the base implementation in the Method class with the breaking out of
        instructions and control flow (Goto, TryCatch, etc) into blocks here.

        This will contain all control flow related "blocks" that can then be parsed later or used to
        build a callgraph

        'code_item' Reference: https://source.android.com/docs/core/runtime/dex-format#code-item
    """

    def __init__(self, code_item):
        self.blocks: list[BasicBlock] = []
        self.code_item = code_item
        self.addr_lookup: dict[int, BasicBlock] = {}
        self._block_id: int = 0

    @property
    def entry(self) -> Optional[BasicBlock]:
        return self.blocks[0] if self.blocks else None

    def build_code_flow(self):
        # 'instr_size' should cover this, but just to be safe, we'll do an extra check
        instrs = self.code_item.instructions

        if not instrs:
            return

        leaders = self._find_leaders(instrs)
        self._build_blocks(instrs, leaders)
        self._connect_edges()
        self._add_exception_edges()


    # "leader" == first instruction of a block
    def _find_leaders(self, instrs):
        leaders = {instrs[0].codepoint}

        for i, instr in enumerate(instrs):
            op = instr.opcode

            def mark_next():
                # make sure we don't accidentally pass out of list of instructions
                if i + 1 < len(instrs):
                    leaders.add(instrs[i + 1].codepoint)

            match op:
                case 0x28:
                    leaders.add(instr.codepoint + sign_extend(instr.vA, 8))
                    mark_next()
                case 0x29:
                    leaders.add(instr.codepoint + sign_extend(instr.vA, 16))
                    mark_next()
                case 0x2a:
                    leaders.add(instr.codepoint + sign_extend(instr.vA, 32))
                    mark_next()
                case _ if 0x32 <= op <= 0x37:
                    leaders.add(instr.codepoint + sign_extend(instr.vA, 16))
                    mark_next()
                case _ if 0x38 <= op <= 0x3d:
                    leaders.add(instr.codepoint + sign_extend(instr.vA, 16))
                    mark_next()
                case _ if op in (0x2b, 0x2c):
                    for rel in instr.switch_table.values():
                        leaders.add(instr.codepoint + rel)
                    mark_next()
                case _ if op in (0x0e, 0x0f, 0x10, 0x11, 0x27):
                    mark_next()

            return leaders


    def _build_blocks(self, instrs, leaders):
        current = None
        for instr in instrs:
            if instr.codepoint in leaders:
                current = BasicBlock()
                current.id = self._block_id
                current.instr_idx_start = len(self.blocks)
                self._block_id += 1
                self.blocks.append(current)
                self.addr_lookup[instr.codepoint] = current

            if current is not None:
                current.instructions.append(instr)

        for block in self.blocks:
            self._classify_block(block)


    def _classify_block(self, block):
        if not block.instructions:
            return
        last = block.last_instruction
        op   = last.opcode

        match op:
            case _ if 0x0e <= op <= 0x11:
                block.block_type = BasicBlockType.RETURN
            case 0x27:
                block.block_type = BasicBlockType.THROW
            case 0x28:
                block.block_type = BasicBlockType.GOTO
                block.next_branch = last.codepoint + sign_extend(last.vA, 8)
            case 0x29:
                block.block_type = BasicBlockType.GOTO
                block.next_branch = last.codepoint + sign_extend(last.vA, 16)
            case 0x2a:
                block.block_type = BasicBlockType.GOTO
                block.next_branch = last.codepoint + sign_extend(last.vA, 32)
            case _ if 0x32 <= op <= 0x37:
                block.block_type = BasicBlockType.IF
                block.next_branch = last.codepoint + sign_extend(last.vC, 16)
            case _ if 0x38 <= op <= 0x3d:
                block.block_type = BasicBlockType.IF
                block.next_branch = last.codepoint + sign_extend(last.vB, 16)
            case _ if op in (0x2b, 0x2c):
                block.block_type = BasicBlockType.SWITCH
            case _:
                block.block_type = BasicBlockType.GENERIC

    def _connect_edges(self):
        sorted_cps = sorted(self.addr_lookup.keys())
        for block in self.blocks:
            if not block.instructions:
                continue

            last = block.last_instruction
            op = last.opcode

            def next_block():
                idx = sorted_cps.index(block.first_codepoint)
                if idx + 1 < len(sorted_cps):
                    return self.addr_lookup[sorted_cps[idx + 1]]
                return None

            def target(codepoint):
                return self.addr_lookup.get(codepoint)

            match op:
                case 0x28:
                    t = target(last.codepoint + sign_extend(last.vA, 8))
                    if t:
                        block.add_successor(t, EdgeKind.JUMP)
                case 0x29:
                    t = target(last.codepoint + sign_extend(last.vA, 16))
                    if t:
                        block.add_successor(t, EdgeKind.JUMP)
                case 0x28:
                    t = target(last.codepoint + sign_extend(last.vA, 32))
                    if t:
                        block.add_successor(t, EdgeKind.JUMP)

                case _ if 0x32 <= op <= 0x37:
                    true_target = target(last.codepoint + sign_extend(last.vC, 16))
                    false_target = next_block()
                    if true_target:
                        block.add_successor(true_target, EdgeKind.JUMP)
                    if false_target:
                        block.add_successor(false_target, EdgeKind.FALL_THROUGH)

                case _ if 0x38 <= op <= 0x3d:
                    true_target = target(last.codepoint + sign_extend(last.vB, 16))
                    false_target = next_block()
                    if true_target:
                        block.add_successor(true_target, EdgeKind.JUMP)
                    if false_target:
                        block.add_successor(false_target, EdgeKind.FALL_THROUGH)

                case _ if op in (0x2b, 0x2c):
                    for key, rel in last.switch_table.items():
                        t = target(last.codepoint + rel)
                        if t:
                            block.add_successor(t, EdgeKind.SWITCH, switch_key=key)
                    next_blk = next_block()
                    if next_blk:
                        block.add_successor(next_blk, EdgeKind.FALL_THROUGH)

                case _ if op in (0x0e, 0x0f, 0x10, 0x11, 0x27):
                    pass # terminators -> they don't have successors

                case _:
                    next_blk = next_block()
                    if next_blk:
                        block.add_successor(next_blk, EdgeKind.FALL_THROUGH)

    def _add_exception_edges(self):
        for try_item in self.code_item.try_items:
            start = try_item.start_addr
            end   = start + try_item.insn_count

            for cp, block in self.addr_lookup.items():
                if not (start <= cp < end):
                    continue

                for handler in self.code_item.handlers:
                    for h in handler.handlers:
                        handler_block = self.addr_lookup[h['addr']]
                        if handler_block:
                            block.add_successor(handler_block, EdgeKind.EXCEPTION)
                    if handler.catch_all_addr:
                        handler_block = self.addr_lookup.get(handler.catch_all_addr)
                        if handler_block:
                            block.add_successor(handler_block, EdgeKind.EXCEPTION)

    def lookup_block_by_codepoint(self, codepoint):
        return self.addr_lookup.get(codepoint)

    def lookup_codeblock_by_idx_offset(self, idx):
        if 0 <= idx < len(self.blocks):
            return self.blocks[idx]
        return None

    def reverse_postorder(self):
        if not self.blocks:
            return []
        visited = set()
        result  = []

        def dfs(block: BasicBlock):
            if block in visited:
                return

            visited.add(block)
            for edge in block.successors:
                if edge.kind != EdgeKind.EXCEPTION:
                    dfs(edge.target)
            result.append(block)

        dfs(self.blocks[0])
        result.reverse()
        return result


# control flow graphb -- builder
class CFGBuilder:

    def __init__(self, method):
        self.method = method
        self.instrs = method.instructions
        self.blocks = {}  # codepoint to block
        self._block_id = 0

    def build(self):
        leaders = self._find_leaders()
        self._build_blocks(leaders)
        self._connect_blocks()
        self._add_exception_edges()
        return CFG(
            entry = self.blocks[0],
            blocks = list(self.blocks.values()),
            method = self.method,
        )


    def _find_leaders(self):
        leaders = {0}
        instrs = self.instrs

        for i, instr in enumerate(instrs):
            op = instr.opcode

            # unconditional branches
            if op in (0x28, 0x29, 0x2a):
                bits = {0x28: 8, 0x29: 16, 0x2a: 32}[op]
                target = instr.codepoint + sign_extend(instr.vA, bits)
                leaders.add(target)
                if i + 1 < len(instrs):
                    leaders.add(instrs[i + 1].codepoint)

            # conditional branches
            elif 0x32 <= op <= 0x37:
                target = instr.codepoint + sign_extend(instr.vC, 16)
                leaders.add(target)
                if i + 1 < len(instrs):
                    leaders.add(instrs[i + 1].codepoint)

            elif op == 0x38 <= op <= 0x3d:
                target = instr.codepoint + sign_extend(instr.vB, 16)
                leaders.add(target)
                if i + 1 < len(instrs):
                    leaders.add(instrs[i + 1].codepoint)

            # Switch
            elif op in (0x2b, 0x2c):
                for rel in instr.switch_table.values():
                    leaders.add(instr.codepoint + rel)
                if i + 1 < len(instrs):
                    leaders.add(instrs[i + 1].codepoint)

            # return / throw (end of block)
            elif 0x0e <= op <= 0x11 or op == 0x27:
                if i + 1 < len(instrs):
                    leaders.add(instrs[i + 1].codepoint)


        return leaders


    def _build_blocks(self, leaders):
        current_block = None
        for instr in self.instrs:
            if instr.codepoint in leaders:
                current_block = BasicBlock(id=self._block_id)
                self._block_id += 1
                self.blocks[instr.codepoint] = current_block

            if current_block is not None:
                current_block.instructions.append(instr)


@dataclass
class CFG:
    entry: BasicBlock
    blocks: list
    method: object

    def reverse_postorder(self):
        visited = set()
        result = []

        def dfs(block):
            if block in visited:
                return
            visited.add(block)

            for edge in block.successors:
                dfs(edge.target)
            result.append(block)

        dfs(self.entry)
        result.reverse()
        return result

