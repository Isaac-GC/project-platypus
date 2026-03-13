"""
Tests for dex/code_block.py - CodeBlock and BasicBlock.
"""
import pytest
import sys
import os
from unittest.mock import MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from dex.code_block import CodeBlock, BasicBlock


# ──────────────────────────────────────────────
# BasicBlock
# ──────────────────────────────────────────────
class TestBasicBlock:
    def test_initial_state(self):
        bb = BasicBlock()
        assert bb.instructions == []
        assert bb.next_branch is None
        assert bb.instr_idx_start == 0

    def test_append_instruction(self):
        bb = BasicBlock()
        fake_instr = MagicMock()
        bb.instructions.append(fake_instr)
        assert len(bb.instructions) == 1
        assert bb.instructions[0] is fake_instr


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────
def _make_instr(opcode: int) -> MagicMock:
    instr = MagicMock()
    instr.opcode = opcode
    return instr


def _make_method(instructions):
    method = MagicMock()
    method.instructions = instructions
    return method


# ──────────────────────────────────────────────
# CodeBlock
# ──────────────────────────────────────────────
class TestCodeBlockInit:
    def test_initial_state(self):
        method = _make_method([])
        cb = CodeBlock(method)
        assert cb.blocks == []
        assert cb.containing_method is method
        assert cb.addr_lookup == {}


class TestCodeBlockBuildFlow:

    def test_empty_instructions_produces_no_blocks(self):
        cb = CodeBlock(_make_method([]))
        cb.build_code_flow()
        assert cb.blocks == []

    def test_return_opcode_splits_block(self):
        """A return opcode (0x0e–0x11) should flush the current block."""
        instrs = [
            _make_instr(0x01),   # regular
            _make_instr(0x0e),   # return-void → splits
            _make_instr(0x01),   # next block regular
        ]
        cb = CodeBlock(_make_method(instrs))
        cb.build_code_flow()
        # The return opcode causes a block to be appended (so... a block must be created)
        assert len(cb.blocks) >= 1

    def test_throw_opcode_splits_block(self):
        instrs = [_make_instr(0x01), _make_instr(0x27)]
        cb = CodeBlock(_make_method(instrs))
        cb.build_code_flow()
        assert len(cb.blocks) >= 1

    def test_goto_opcode_splits_block(self):
        for goto_op in [0x28, 0x29, 0x2a]:
            instrs = [_make_instr(0x01), _make_instr(goto_op)]
            cb = CodeBlock(_make_method(instrs))
            cb.build_code_flow()
            assert len(cb.blocks) >= 1, f"'goto' opcode {hex(goto_op)} should split block"

    def test_if_opcode_splits_block(self):
        for if_op in [0x32, 0x33, 0x37, 0x3d]:
            instrs = [_make_instr(0x01), _make_instr(if_op)]
            cb = CodeBlock(_make_method(instrs))
            cb.build_code_flow()
            assert len(cb.blocks) >= 1, f"'if' opcode {hex(if_op)} should split block"

    def test_regular_opcodes_accumulate_in_block(self):
        """Regular instructions should stay inside a single basic block."""
        regular_opcodes = [0x01, 0x02, 0x03, 0x12, 0x13]
        instrs = [_make_instr(op) for op in regular_opcodes]
        cb = CodeBlock(_make_method(instrs))
        cb.build_code_flow()
        # No terminators → no blocks flushed to the list
        assert len(cb.blocks) == 0

    def test_multiple_returns_produce_multiple_blocks(self):
        instrs = [
            _make_instr(0x01),
            _make_instr(0x0e),  # return → flush
            _make_instr(0x02),
            _make_instr(0x0f),  # return → flush
        ]
        cb = CodeBlock(_make_method(instrs))
        cb.build_code_flow()
        assert len(cb.blocks) == 2


class TestCodeBlockLookup:
    def test_lookup_existing_block(self):
        cb = CodeBlock(_make_method([]))
        bb = BasicBlock()
        bb.instr_idx_start = 5
        cb.blocks.append(bb)
        assert cb.lookup_codeblock_by_idx_offset(5) is bb

    def test_lookup_missing_returns_none(self):
        cb = CodeBlock(_make_method([]))
        assert cb.lookup_codeblock_by_idx_offset(999) is None

    def test_lookup_first_block_at_zero(self):
        cb = CodeBlock(_make_method([]))
        bb = BasicBlock()
        bb.instr_idx_start = 0
        cb.blocks.append(bb)
        assert cb.lookup_codeblock_by_idx_offset(0) is bb
