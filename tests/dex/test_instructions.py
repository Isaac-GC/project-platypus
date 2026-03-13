"""
Tests for dex/instructions_new.py - helper functions, enums, and instruction classes.
"""
import pytest
import sys
import os
import io
from unittest.mock import MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from dex.instructions_new import (
    reg_ops_helper,
    ControlFlow,
    OpCodeNotFoundError,
    InstructionReturn,
    InstructionBase,
    Nop,
    Move,
    MoveResult,
    Return,
    Const,
    Monitor,
    CheckCast,
    InstanceOf,
    ArrLength,
    NewInstance,
    Array,
    Throw,
    Goto,
    Switch,
    Cmp,
    If,
    IfZ,
    ArrayOp,
    IGet,
    IPut,
    SGet,
    SPut,
    InvokeKind,
    InvokeKindRange,
    UnOp,
    BinOp,
    BinOp2Addr,
    BinOpLit,
    InvokePolymorphic,
    InvokeCustom,
    ConstMethod,
)


# ──────────────────────────────────────────────
# Shared helpers
# ──────────────────────────────────────────────

def _regs(size=32):
    return [0] * size


def _mem(**kwargs):
    m = MagicMock()
    for k, v in kwargs.items():
        setattr(m, k, v)
    return m


# ──────────────────────────────────────────────
# reg_ops_helper
# ──────────────────────────────────────────────

class TestRegOpsHelper:
    def test_add_int(self):          assert reg_ops_helper(0x0, 0x0, 3, 4) == 7
    def test_sub_int(self):          assert reg_ops_helper(0x1, 0x0, 10, 6) == 4
    def test_mul_int(self):          assert reg_ops_helper(0x2, 0x0, 6, 7) == 42
    def test_div_int(self):          assert reg_ops_helper(0x3, 0x0, 20, 4) == 5
    def test_div_zero(self):         assert reg_ops_helper(0x3, 0x0, 10, 0) == 0
    def test_mod_int(self):          assert reg_ops_helper(0x4, 0x0, 10, 3) == 1
    def test_and_int(self):          assert reg_ops_helper(0x5, 0x0, 0xFF, 0x0F) == 0x0F
    def test_or_int(self):           assert reg_ops_helper(0x6, 0x0, 0xF0, 0x0F) == 0xFF
    def test_xor_int(self):          assert reg_ops_helper(0x7, 0x0, 0xFF, 0x0F) == 0xF0
    def test_shl_int(self):          assert reg_ops_helper(0x8, 0x0, 1, 4) == 16
    def test_shr_int(self):          assert reg_ops_helper(0x9, 0x0, 32, 2) == 8
    def test_zero_zero(self):        assert reg_ops_helper(0x0, 0x0, 0, 0) == 0
    def test_long_operand(self):     assert reg_ops_helper(0x0, 0x1, 1, 2) == 3

    def test_int_result_signed_overflow(self):
        result = reg_ops_helper(0x0, 0x0, 0x7FFFFFFF, 1)
        assert result < 0


# ──────────────────────────────────────────────
# ControlFlow / OpCodeNotFoundError / InstructionReturn
# ──────────────────────────────────────────────

class TestControlFlow:
    def test_values(self):
        assert ControlFlow.Terminate.value   == 0x1
        assert ControlFlow.GoTo.value        == 0x2
        assert ControlFlow.Branch.value      == 0x3
        assert ControlFlow.FallThrough.value == 0x4

    def test_unique(self):
        vals = [c.value for c in ControlFlow]
        assert len(vals) == len(set(vals))


class TestOpCodeNotFoundError:
    def test_raises(self):
        with pytest.raises(OpCodeNotFoundError):
            raise OpCodeNotFoundError(0xDE)

    def test_message_contains_hex(self):
        with pytest.raises(OpCodeNotFoundError, match="0xab"):
            raise OpCodeNotFoundError(0xAB)

    def test_is_exception(self):
        assert issubclass(OpCodeNotFoundError, Exception)


class TestInstructionReturn:
    def test_fields(self):
        ir = InstructionReturn(42, True, [1, 2])
        assert ir.ret == 42
        assert ir.is_external_call is True
        assert ir.parameters == [1, 2]

    def test_no_call(self):
        ir = InstructionReturn(1, False, [])
        assert not ir.is_external_call


# ──────────────────────────────────────────────
# Nop
# ──────────────────────────────────────────────

class TestNop:
    def test_fetch_fmt(self):
        n = Nop(0x00, MagicMock())
        n.fetch()
        assert n.fmt == 0x10

    def test_execute_fallthrough(self):
        n = Nop(0x00, MagicMock())
        n.fetch()
        result = n.execute(MagicMock(), _regs())
        assert isinstance(result, InstructionReturn)
        assert result.ret == 1

    def test_decode_sets_address(self):
        n = Nop(0x00, MagicMock())
        n.fetch()
        fd = io.BytesIO(b'\x00\x00')
        fd.read(1)
        n.decode(fd)
        assert n.address == 1


# ──────────────────────────────────────────────
# Move
# ──────────────────────────────────────────────

class TestMove:
    def test_fetch_normal(self):
        m = Move(0x01, MagicMock())
        m.fetch()
        assert m.fmt == 0x12
        assert "move" in m.prefix

    def test_fetch_wide(self):
        m = Move(0x04, MagicMock())
        m.fetch()
        assert "wide" in m.prefix

    def test_fetch_object(self):
        m = Move(0x07, MagicMock())
        m.fetch()
        assert "object" in m.prefix

    def test_fetch_from16(self):
        m = Move(0x02, MagicMock())
        m.fetch()
        assert m.suffix == "from16"

    def test_fetch_16(self):
        m = Move(0x03, MagicMock())
        m.fetch()
        assert m.suffix == "16"

    def test_fetch_invalid(self):
        with pytest.raises(OpCodeNotFoundError):
            Move(0xFF, MagicMock()).fetch()

    def test_execute_normal_copies_register(self):
        m = Move(0x01, MagicMock())
        m.fetch()
        m.vA = 0
        m.vB = 1
        regs = [0, 99]
        mem = _mem()
        m.execute(mem, regs)
        assert regs[0] == 99
        assert mem.last_return == 0

    def test_execute_wide_copies_two_registers(self):
        m = Move(0x04, MagicMock())
        m.fetch()
        m.vA = 0
        m.vB = 2
        regs = [0, 0, 0xDEAD, 0xBEEF]
        m.execute(_mem(), regs)
        assert regs[0] == 0xDEAD
        assert regs[1] == 0xBEEF


# ──────────────────────────────────────────────
# MoveResult
# ──────────────────────────────────────────────

class TestMoveResult:
    def test_fetch_all_variants(self):
        for op in [0x0a, 0x0b, 0x0c, 0x0d]:
            MoveResult(op, MagicMock()).fetch()  # should not raise

    def test_fetch_invalid(self):
        with pytest.raises(OpCodeNotFoundError):
            MoveResult(0xFF, MagicMock()).fetch()

    def test_execute_non_wide(self):
        mr = MoveResult(0x0a, MagicMock())
        mr.fetch()
        mr.vA = 3
        mem = _mem(last_return=42)
        regs = _regs()
        mr.execute(mem, regs)
        assert regs[3] == 42

    def test_execute_wide(self):
        mr = MoveResult(0x0b, MagicMock())
        mr.fetch()
        mr.vA = 0
        mem = _mem(last_return=(0x1111, 0x2222))
        regs = _regs()
        mr.execute(mem, regs)
        assert regs[0] == 0x1111
        assert regs[1] == 0x2222

    def test_execute_wide_null_return(self):
        mr = MoveResult(0x0b, MagicMock())
        mr.fetch()
        mr.vA = 0
        mem = _mem(last_return=None)
        regs = _regs()
        mr.execute(mem, regs)
        assert regs[0] == 0
        assert regs[1] == 0


# ──────────────────────────────────────────────
# Return
# ──────────────────────────────────────────────

class TestReturn:
    def test_fetch_void(self):
        r = Return(0x0e, MagicMock())
        r.fetch()
        assert r.prefix == "return-void"
        assert r.control_flow == ControlFlow.Terminate

    def test_fetch_return(self):
        Return(0x0f, MagicMock()).fetch()

    def test_fetch_wide(self):
        r = Return(0x10, MagicMock())
        r.fetch()
        assert r.prefix == "return-wide"

    def test_fetch_object(self):
        r = Return(0x11, MagicMock())
        r.fetch()
        assert r.prefix == "return-object"

    def test_fetch_invalid(self):
        with pytest.raises(OpCodeNotFoundError):
            Return(0xAA, MagicMock()).fetch()

    def test_execute_void_no_side_effect(self):
        r = Return(0x0e, MagicMock())
        r.fetch()
        r.vA = 0
        r.execute(_mem(), _regs())

    def test_execute_sets_last_return(self):
        r = Return(0x0f, MagicMock())
        r.fetch()
        r.vA = 2
        mem = _mem()
        regs = _regs()
        regs[2] = 99
        r.execute(mem, regs)
        assert mem.last_return == 99

    def test_execute_wide_sets_tuple(self):
        r = Return(0x10, MagicMock())
        r.fetch()
        r.vA = 0
        mem = _mem()
        regs = _regs()
        regs[0] = 0xDEAD
        regs[1] = 0xBEEF
        r.execute(mem, regs)
        assert mem.last_return == (0xDEAD, 0xBEEF)


# ──────────────────────────────────────────────
# Const
# ──────────────────────────────────────────────

class TestConst:
    def test_fetch_const4(self):
        c = Const(0x12, MagicMock())
        c.fetch()
        assert c.suffix == "4"

    def test_fetch_const16(self):
        c = Const(0x13, MagicMock())
        c.fetch()
        assert c.suffix == "16"

    def test_fetch_const_string(self):
        c = Const(0x1a, MagicMock())
        c.fetch()
        assert "string" in c.prefix

    def test_fetch_const_class(self):
        Const(0x1c, MagicMock()).fetch()

    def test_fetch_invalid(self):
        with pytest.raises(OpCodeNotFoundError):
            Const(0x99, MagicMock()).fetch()

    def test_execute_const4_sets_register(self):
        c = Const(0x12, MagicMock())
        c.fetch()
        c.vA = 0
        c.vB = 7
        regs = _regs()
        c.execute(_mem(), regs)
        assert regs[0] == 7

    def test_execute_const_high16_shifts(self):
        c = Const(0x15, MagicMock())
        c.fetch()
        c.vA = 0
        c.vB = 1
        regs = _regs()
        c.execute(_mem(), regs)
        assert regs[0] == 1 << 16

    def test_execute_const_wide_splits_registers(self):
        c = Const(0x16, MagicMock())
        c.fetch()
        c.vA = 0
        c.vB = 0x1_0000_0005
        regs = _regs()
        c.execute(_mem(), regs)
        assert regs[1] == c.vB & 0xFFFFFFFF
        assert regs[0] == c.vB >> 32

    def test_execute_const_string_lookup(self):
        c = Const(0x1a, MagicMock())
        c.fetch()
        c.vA = 0
        c.vB = 3
        mock_string = MagicMock()
        mock_string.value.raw_data = b"hello"
        mem = _mem()
        mem.dex.string_ids = {3: mock_string}
        regs = _regs()
        c.execute(mem, regs)
        assert regs[0] == b"hello"

    def test_execute_const_class_sets_index(self):
        c = Const(0x1c, MagicMock())
        c.fetch()
        c.vA = 0
        c.vB = 42
        regs = _regs()
        c.execute(_mem(), regs)
        assert regs[0] == 42


# ──────────────────────────────────────────────
# Monitor
# ──────────────────────────────────────────────

class TestMonitor:
    def test_fetch_sets_fmt(self):
        m = Monitor(0x1d, MagicMock())
        m.fetch()
        assert m.fmt == 0x11

    def test_decode_enter_instruction_str(self):
        m = Monitor(0x1d, MagicMock())
        m.fetch()
        fd = io.BytesIO(b'\x1d\x02')
        fd.read(1)
        m.decode(fd)
        assert "enter" in m.instruction_str

    def test_decode_exit_instruction_str(self):
        m = Monitor(0x1e, MagicMock())
        m.fetch()
        fd = io.BytesIO(b'\x1e\x02')
        fd.read(1)
        m.decode(fd)
        assert "exit" in m.instruction_str


# ──────────────────────────────────────────────
# CheckCast
# ──────────────────────────────────────────────

class TestCheckCast:
    def test_fetch(self):
        cc = CheckCast(0x1f, MagicMock())
        cc.fetch()
        assert cc.fmt == 0x112222
        assert cc.prefix == "check-cast"

    def test_decode_sets_instruction_str(self):
        cc = CheckCast(0x1f, MagicMock())
        cc.fetch()
        cc.vA = 1
        cc.vB = 5
        cc.instruction_str = f"check-cast {cc.vA} v{cc.vB}"
        assert "check-cast" in cc.instruction_str


# ──────────────────────────────────────────────
# InstanceOf
# ──────────────────────────────────────────────

class TestInstanceOf:
    def test_fetch(self):
        io_instr = InstanceOf(0x20, MagicMock())
        io_instr.fetch()
        assert io_instr.fmt == 0x123333
        assert io_instr.prefix == "instanceof"

    def test_decode_sets_instruction_str(self):
        io_instr = InstanceOf(0x20, MagicMock())
        io_instr.fetch()
        io_instr.vA = 0
        io_instr.vB = 1
        io_instr.vC = 2
        io_instr.instruction_str = f"instanceof v{io_instr.vA} v{io_instr.vB} @{io_instr.vC}"
        assert "instanceof" in io_instr.instruction_str


# ──────────────────────────────────────────────
# ArrLength
# ──────────────────────────────────────────────

class TestArrLength:
    def test_fetch_valid(self):
        al = ArrLength(0x21, MagicMock())
        al.fetch()
        assert al.prefix == "array-length"

    def test_fetch_invalid(self):
        with pytest.raises(OpCodeNotFoundError):
            ArrLength(0x99, MagicMock()).fetch()

    def test_execute_list_length(self):
        al = ArrLength(0x21, MagicMock())
        al.fetch()
        al.vA, al.vB = 0, 1
        regs = [0, [1, 2, 3, 4, 5]]
        al.execute(MagicMock(), regs)
        assert regs[0] == 5

    def test_execute_non_iterable_returns_zero(self):
        al = ArrLength(0x21, MagicMock())
        al.fetch()
        al.vA, al.vB = 0, 1
        regs = [0, 42]
        al.execute(MagicMock(), regs)
        assert regs[0] == 0

    def test_execute_empty_list(self):
        al = ArrLength(0x21, MagicMock())
        al.fetch()
        al.vA, al.vB = 0, 1
        regs = [0, []]
        al.execute(MagicMock(), regs)
        assert regs[0] == 0


# ──────────────────────────────────────────────
# NewInstance
# ──────────────────────────────────────────────

class TestNewInstance:
    def test_fetch_valid(self):
        ni = NewInstance(0x22, MagicMock())
        ni.fetch()
        assert ni.prefix == "new-instance"

    def test_fetch_invalid(self):
        with pytest.raises(OpCodeNotFoundError):
            NewInstance(0x99, MagicMock()).fetch()

    def test_execute_string_type(self):
        ni = NewInstance(0x22, MagicMock())
        ni.fetch()
        ni.vA, ni.vB = 0, 1
        mem = _mem()
        mem.dex.type_ids[1].type_name = "Ljava/lang/String;"
        regs = _regs()
        ni.execute(mem, regs)
        assert regs[0] == ""

    def test_execute_non_string_type(self):
        ni = NewInstance(0x22, MagicMock())
        ni.fetch()
        ni.vA, ni.vB = 0, 1
        mem = _mem()
        mem.dex.type_ids[1].type_name = "Ljava/util/ArrayList;"
        regs = _regs()
        ni.execute(mem, regs)
        assert regs[0] == "Ljava/util/ArrayList;"


# ──────────────────────────────────────────────
# Array
# ──────────────────────────────────────────────

class TestArray:
    def test_fetch_new_array(self):
        a = Array(0x23, MagicMock())
        a.fetch()
        assert a.prefix == "new-array"

    def test_fetch_filled_new_array(self):
        a = Array(0x24, MagicMock())
        a.fetch()
        assert a.prefix == "filled-new-array"

    def test_fetch_fill_array_data(self):
        a = Array(0x26, MagicMock())
        a.fetch()
        assert a.prefix == "fill-array-data"

    def test_fetch_invalid(self):
        with pytest.raises(OpCodeNotFoundError):
            Array(0x99, MagicMock()).fetch()

    def test_execute_new_array_creates_list(self):
        a = Array(0x23, MagicMock())
        a.fetch()
        a.vA, a.vB, a.vC = 0, 1, 0
        regs = [None, 4]
        a.execute(MagicMock(), regs)
        assert isinstance(regs[0], list)
        assert len(regs[0]) == 4

    def test_execute_new_array_invalid_size(self):
        a = Array(0x23, MagicMock())
        a.fetch()
        a.vA, a.vB, a.vC = 0, 1, 0
        regs = [None, "not_a_number"]
        a.execute(MagicMock(), regs)
        assert regs[0] == []


# ──────────────────────────────────────────────
# Throw
# ──────────────────────────────────────────────

class TestThrow:
    def test_fetch(self):
        t = Throw(0x27, MagicMock())
        t.fetch()
        assert t.prefix == "throw"
        assert t.control_flow == ControlFlow.Terminate

    def test_execute_sets_exception(self):
        t = Throw(0x27, MagicMock())
        t.fetch()
        t.vA = 5
        mem = _mem()
        t.execute(mem, _regs())
        assert mem.last_exception == 5


# ──────────────────────────────────────────────
# Goto
# ──────────────────────────────────────────────

class TestGoto:
    def test_fetch_goto8(self):
        g = Goto(0x28, MagicMock())
        g.fetch()
        assert g.fmt == 0xAA
        assert g.control_flow == ControlFlow.GoTo

    def test_fetch_goto16(self):
        g = Goto(0x29, MagicMock())
        g.fetch()
        assert g.suffix == "16"

    def test_fetch_goto32(self):
        g = Goto(0x2a, MagicMock())
        g.fetch()
        assert g.suffix == "32"

    def test_fetch_invalid(self):
        with pytest.raises(OpCodeNotFoundError):
            Goto(0x99, MagicMock()).fetch()

    def test_execute_returns_target(self):
        g = Goto(0x28, MagicMock())
        g.fetch()
        g.vA = 5
        assert g.execute(MagicMock(), _regs()) == 10

    def test_execute_negative_offset(self):
        g = Goto(0x28, MagicMock())
        g.fetch()
        g.vA = -3
        assert g.execute(MagicMock(), _regs()) == -6


# ──────────────────────────────────────────────
# Switch
# ──────────────────────────────────────────────

class TestSwitch:
    def test_fetch(self):
        s = Switch(0x2b, MagicMock())
        s.fetch()
        assert s.prefix == "switch"

    def test_initial_switch_table_empty(self):
        s = Switch(0x2b, MagicMock())
        assert s.switch_table == {}

    def test_execute_branch_found(self):
        s = Switch(0x2b, MagicMock())
        s.fetch()
        s.vA = 0
        s.address = 100
        s.switch_table = {1: 10, 2: 20, 3: 30}
        regs = [2]
        mem = _mem()
        s.execute(mem, regs)
        assert mem.last_return == 100 + 20 + 2

    def test_execute_no_branch_found_does_not_set_last_return(self):
        s = Switch(0x2b, MagicMock())
        s.fetch()
        s.vA = 0
        s.switch_table = {1: 10}
        regs = [99]
        mem = MagicMock(spec=[])  # no attributes — would raise AttributeError if set
        s.execute(mem, regs)     # should not raise


# ──────────────────────────────────────────────
# Cmp
# ──────────────────────────────────────────────

class TestCmp:
    def test_fetch(self):
        c = Cmp(0x2d, MagicMock())
        c.fetch()
        assert c.prefix == "cmp"

    def test_execute_a_gt_b(self):
        c = Cmp(0x2d, MagicMock())
        c.fetch()
        c.vA, c.vB, c.vC = 0, 1, 2
        regs = [0, 10, 5]
        c.execute(MagicMock(), regs)
        assert regs[0] == 1

    def test_execute_a_lt_b(self):
        c = Cmp(0x2d, MagicMock())
        c.fetch()
        c.vA, c.vB, c.vC = 0, 1, 2
        regs = [0, 5, 10]
        c.execute(MagicMock(), regs)
        assert regs[0] == -1

    def test_execute_equal(self):
        c = Cmp(0x2d, MagicMock())
        c.fetch()
        c.vA, c.vB, c.vC = 0, 1, 2
        regs = [0, 7, 7]
        c.execute(MagicMock(), regs)
        assert regs[0] == 0

    def test_execute_zero_operand_0x2d_gives_minus1(self):
        c = Cmp(0x2d, MagicMock())
        c.fetch()
        c.vA, c.vB, c.vC = 0, 1, 2
        regs = [0, 0, 5]
        c.execute(MagicMock(), regs)
        assert regs[0] == -1

    def test_execute_zero_operand_0x2e_gives_plus1(self):
        c = Cmp(0x2e, MagicMock())
        c.fetch()
        c.vA, c.vB, c.vC = 0, 1, 2
        regs = [0, 0, 5]
        c.execute(MagicMock(), regs)
        assert regs[0] == 1


# ──────────────────────────────────────────────
# If
# ──────────────────────────────────────────────

class TestIf:
    def test_fetch_all_variants(self):
        for opcode, substr in [(0x32, "eq"), (0x33, "ne"), (0x34, "lt"),
                                (0x35, "ge"), (0x36, "gt"), (0x37, "le")]:
            instr = If(opcode, MagicMock())
            instr.fetch()
            assert substr in instr.prefix
            assert instr.control_flow == ControlFlow.Branch

    def test_fetch_invalid(self):
        with pytest.raises(OpCodeNotFoundError):
            If(0x99, MagicMock()).fetch()

    def test_execute_eq_taken(self):
        instr = If(0x32, MagicMock())
        instr.fetch()
        instr.vA, instr.vB, instr.vC = 0, 1, 5
        mem = _mem()
        instr.execute(mem, [10, 10])
        assert mem.last_return == 10

    def test_execute_eq_not_taken(self):
        instr = If(0x32, MagicMock())
        instr.fetch()
        instr.vA, instr.vB, instr.vC = 0, 1, 5
        mem = _mem()
        instr.execute(mem, [10, 20])
        assert mem.last_return == 1

    def test_execute_ne_taken(self):
        instr = If(0x33, MagicMock())
        instr.fetch()
        instr.vA, instr.vB, instr.vC = 0, 1, 4
        mem = _mem()
        instr.execute(mem, [1, 2])
        assert mem.last_return == 8

    def test_execute_lt_taken(self):
        instr = If(0x34, MagicMock())
        instr.fetch()
        instr.vA, instr.vB, instr.vC = 0, 1, 3
        mem = _mem()
        instr.execute(mem, [1, 5])
        assert mem.last_return == 6

    def test_execute_ge_taken(self):
        instr = If(0x35, MagicMock())
        instr.fetch()
        instr.vA, instr.vB, instr.vC = 0, 1, 2
        mem = _mem()
        instr.execute(mem, [5, 5])
        assert mem.last_return == 4

    def test_execute_gt_taken(self):
        instr = If(0x36, MagicMock())
        instr.fetch()
        instr.vA, instr.vB, instr.vC = 0, 1, 2
        mem = _mem()
        instr.execute(mem, [10, 5])
        assert mem.last_return == 4

    def test_execute_le_taken(self):
        instr = If(0x37, MagicMock())
        instr.fetch()
        instr.vA, instr.vB, instr.vC = 0, 1, 3
        mem = _mem()
        instr.execute(mem, [5, 5])
        assert mem.last_return == 6


# ──────────────────────────────────────────────
# IfZ
# ──────────────────────────────────────────────

class TestIfZ:
    def test_fetch_all_variants(self):
        for opcode, substr in [(0x38, "eqz"), (0x39, "nez"), (0x3a, "ltz"),
                                (0x3b, "gez"), (0x3c, "gtz"), (0x3d, "lez")]:
            instr = IfZ(opcode, MagicMock())
            instr.fetch()
            assert substr in instr.prefix

    def test_fetch_invalid(self):
        with pytest.raises(OpCodeNotFoundError):
            IfZ(0x99, MagicMock()).fetch()

    def test_execute_nez_nonzero_taken(self):
        instr = IfZ(0x39, MagicMock())
        instr.fetch()
        instr.vA, instr.vB = 0, 4
        mem = _mem()
        instr.execute(mem, [5])
        assert mem.last_return == 8

    def test_execute_ltz_negative_taken(self):
        instr = IfZ(0x3a, MagicMock())
        instr.fetch()
        instr.vA, instr.vB = 0, 3
        mem = _mem()
        instr.execute(mem, [-1])
        assert mem.last_return == 6

    def test_execute_gez_positive_taken(self):
        instr = IfZ(0x3b, MagicMock())
        instr.fetch()
        instr.vA, instr.vB = 0, 2
        mem = _mem()
        instr.execute(mem, [1])
        assert mem.last_return == 4

    def test_execute_gtz_positive_taken(self):
        instr = IfZ(0x3c, MagicMock())
        instr.fetch()
        instr.vA, instr.vB = 0, 2
        mem = _mem()
        instr.execute(mem, [5])
        assert mem.last_return == 4

    def test_execute_lez_negative_taken(self):
        instr = IfZ(0x3d, MagicMock())
        instr.fetch()
        instr.vA, instr.vB = 0, 2
        mem = _mem()
        instr.execute(mem, [-1])
        assert mem.last_return == 4


# ──────────────────────────────────────────────
# ArrayOp
# ──────────────────────────────────────────────

class TestArrayOp:
    def test_fetch_aget_all_variants(self):
        for op in range(0x44, 0x4b):
            a = ArrayOp(op, MagicMock())
            a.fetch()
            assert "aget" in a.prefix

    def test_fetch_aput_all_variants(self):
        for op in range(0x4b, 0x52):
            a = ArrayOp(op, MagicMock())
            a.fetch()
            assert "aput" in a.prefix

    def test_fetch_invalid(self):
        with pytest.raises(OpCodeNotFoundError):
            ArrayOp(0x99, MagicMock()).fetch()

    def test_execute_aget(self):
        a = ArrayOp(0x44, MagicMock())
        a.fetch()
        a.vA, a.vB, a.vC = 0, 1, 2
        regs = [None, [10, 20, 30], 1]
        a.execute(MagicMock(), regs)
        assert regs[0] == 20

    def test_execute_aput(self):
        a = ArrayOp(0x4b, MagicMock())
        a.fetch()
        a.vA, a.vB, a.vC = 0, 1, 2
        regs = [99, [0, 0, 0], 1]
        a.execute(MagicMock(), regs)
        assert regs[1][1] == 99

    def test_execute_aget_null_array_does_not_raise(self):
        a = ArrayOp(0x44, MagicMock())
        a.fetch()
        a.vA, a.vB, a.vC = 0, 1, 2
        regs = [None, None, 0]
        a.execute(MagicMock(), regs)


# ──────────────────────────────────────────────
# IGet
# ──────────────────────────────────────────────

class TestIGet:
    def test_fetch_valid_range(self):
        for op in range(0x52, 0x59):
            ig = IGet(op, MagicMock())
            ig.fetch()
            assert "iget" in ig.prefix

    def test_fetch_invalid(self):
        with pytest.raises(OpCodeNotFoundError):
            IGet(0x99, MagicMock()).fetch()

    def test_execute_basic(self):
        ig = IGet(0x52, MagicMock())
        ig.fetch()
        ig.vA, ig.vB, ig.vC = 0, 1, 42
        mem = _mem()
        mem.instance_fields = {42: 999}
        regs = _regs()
        ig.execute(mem, regs)
        assert regs[0] == 999

    def test_execute_missing_field_defaults_zero(self):
        ig = IGet(0x52, MagicMock())
        ig.fetch()
        ig.vA, ig.vB, ig.vC = 0, 1, 99
        mem = _mem()
        mem.instance_fields = {}
        regs = _regs()
        ig.execute(mem, regs)
        assert regs[0] == 0

    def test_execute_wide_splits_registers(self):
        ig = IGet(0x53, MagicMock())
        ig.fetch()
        ig.vA, ig.vB, ig.vC = 0, 1, 10
        val = 0x0000_0001_0000_0002
        mem = _mem()
        mem.instance_fields = {10: val}
        regs = _regs()
        ig.execute(mem, regs)
        assert regs[1] == val & 0xFFFFFFFF
        assert regs[0] == val >> 32


# ──────────────────────────────────────────────
# IPut
# ──────────────────────────────────────────────

class TestIPut:
    def test_fetch_valid(self):
        ip = IPut(0x59, MagicMock())
        ip.fetch()
        assert "iput" in ip.prefix

    def test_fetch_invalid(self):
        with pytest.raises(OpCodeNotFoundError):
            IPut(0x20, MagicMock()).fetch()

    def test_execute_stores_value(self):
        ip = IPut(0x59, MagicMock())
        ip.fetch()
        ip.vA, ip.vB, ip.vC = 0, 1, 7
        mem = _mem()
        mem.instance_fields = {}
        regs = _regs()
        regs[0] = 123
        ip.execute(mem, regs)
        assert mem.instance_fields[7] == 123


# ──────────────────────────────────────────────
# SGet
# ──────────────────────────────────────────────

class TestSGet:
    def test_fetch_valid_range(self):
        for op in range(0x60, 0x67):
            sg = SGet(op, MagicMock())
            sg.fetch()
            assert "sget" in sg.prefix

    def test_fetch_invalid(self):
        with pytest.raises(OpCodeNotFoundError):
            SGet(0x99, MagicMock()).fetch()

    def test_execute_basic(self):
        sg = SGet(0x60, MagicMock())
        sg.fetch()
        sg.vA, sg.vB = 0, 5
        mem = _mem()
        mem.static_fields = {5: 77}
        regs = _regs()
        sg.execute(mem, regs)
        assert regs[0] == 77

    def test_execute_missing_defaults_none(self):
        sg = SGet(0x60, MagicMock())
        sg.fetch()
        sg.vA, sg.vB = 0, 99
        mem = _mem()
        mem.static_fields = {}
        regs = _regs()
        sg.execute(mem, regs)
        assert regs[0] is None

    def test_execute_wide_splits_registers(self):
        sg = SGet(0x61, MagicMock())
        sg.fetch()
        sg.vA, sg.vB = 0, 3
        val = 0x0000_0001_0000_0002
        mem = _mem()
        mem.static_fields = {3: val}
        regs = _regs()
        sg.execute(mem, regs)
        assert regs[1] == val & 0xFFFFFFFF
        assert regs[0] == val >> 32

    def test_execute_wide_null_resets(self):
        sg = SGet(0x61, MagicMock())
        sg.fetch()
        sg.vA, sg.vB = 0, 3
        mem = _mem()
        mem.static_fields = {3: None}
        regs = _regs()
        sg.execute(mem, regs)
        assert regs[0] == 0
        assert regs[1] == 0


# ──────────────────────────────────────────────
# SPut
# ──────────────────────────────────────────────

class TestSPut:
    def test_fetch_valid_range(self):
        for op in range(0x67, 0x6e):
            sp = SPut(op, MagicMock())
            sp.fetch()
            assert "sput" in sp.prefix

    def test_fetch_invalid(self):
        with pytest.raises(OpCodeNotFoundError):
            SPut(0x99, MagicMock()).fetch()

    def test_execute_stores_value(self):
        sp = SPut(0x67, MagicMock())
        sp.fetch()
        sp.vA, sp.vB = 0, 3
        mem = _mem()
        mem.static_fields = {}
        regs = _regs()
        regs[0] = 55
        sp.execute(mem, regs)
        assert mem.static_fields[3] == 55

    def test_execute_wide(self):
        # prior field value is irrelevant — it's overwritten by registers[vA] first
        sp = SPut(0x68, MagicMock())
        sp.fetch()
        sp.vA, sp.vB = 0, 2
        mem = _mem()
        mem.static_fields = {}
        regs = _regs()
        regs[0] = 0xDEAD
        regs[1] = 0xBEEF
        sp.execute(mem, regs)
        assert mem.static_fields[2] == (0xDEAD << 32) + 0xBEEF

    def test_execute_wide_null_resets_field(self):
        # registers[vA] must be None to trigger TypeError, not the field value
        sp = SPut(0x68, MagicMock())
        sp.fetch()
        sp.vA, sp.vB = 0, 2
        mem = _mem()
        mem.static_fields = {2: 0}
        regs = _regs()
        regs[0] = None
        regs[1] = 99
        sp.execute(mem, regs)
        assert mem.static_fields[2] == 0

# ──────────────────────────────────────────────
# InvokeKind
# ──────────────────────────────────────────────

class TestInvokeKind:
    def test_fetch_all_variants(self):
        names = ["virtual", "super", "direct", "static", "interface"]
        for i, op in enumerate(range(0x6e, 0x73)):
            ik = InvokeKind(op, MagicMock())
            ik.fetch()
            assert names[i] in ik.prefix

    def test_fetch_invalid(self):
        with pytest.raises(OpCodeNotFoundError):
            InvokeKind(0x99, MagicMock()).fetch()

    def test_execute_returns_instruction_return(self):
        ik = InvokeKind(0x6e, MagicMock())
        ik.fetch()
        ik.vA, ik.vB = 2, 10
        ik.vC, ik.vD, ik.vE, ik.vF, ik.vG = 1, 2, 3, 4, 5
        mem = _mem()
        mem.dex.lookup_method.return_value = "some_method"
        result = ik.execute(mem, _regs())
        assert isinstance(result, InstructionReturn)
        assert result.is_external_call is True
        assert result.ret == "some_method"

    def test_execute_params_sliced_by_vA(self):
        ik = InvokeKind(0x6e, MagicMock())
        ik.fetch()
        ik.vA = 3
        ik.vB = 0
        ik.vC, ik.vD, ik.vE, ik.vF, ik.vG = 10, 20, 30, 40, 50
        mem = _mem()
        mem.dex.lookup_method.return_value = None
        result = ik.execute(mem, _regs())
        assert result.parameters == [10, 20, 30]


# ──────────────────────────────────────────────
# InvokeKindRange
# ──────────────────────────────────────────────

class TestInvokeKindRange:
    def test_fetch_all_variants(self):
        names = ["virtual", "super", "direct", "static", "interface"]
        for i, op in enumerate(range(0x74, 0x79)):
            ikr = InvokeKindRange(op, MagicMock())
            ikr.fetch()
            assert names[i] in ikr.prefix

    def test_fetch_invalid(self):
        with pytest.raises(OpCodeNotFoundError):
            InvokeKindRange(0x99, MagicMock()).fetch()

    def test_execute_returns_instruction_return(self):
        ikr = InvokeKindRange(0x74, MagicMock())
        ikr.fetch()
        ikr.vA = 3
        ikr.vB = 5
        ikr.vC = 10
        mem = _mem()
        mem.dex.lookup_method.return_value = "method_ref"
        result = ikr.execute(mem, _regs())
        assert isinstance(result, InstructionReturn)
        assert result.parameters == [10, 11, 12]


# ──────────────────────────────────────────────
# UnOp
# ──────────────────────────────────────────────

class TestUnOp:
    def test_fetch_all_prefixes(self):
        expected = {
            0x7b: "neg-int",     0x7c: "not-int",
            0x7d: "neg-long",    0x7e: "not-long",
            0x7f: "neg-float",   0x80: "neg-double",
            0x81: "int-to-long", 0x82: "int-to-float",
            0x83: "int-to-double", 0x84: "long-to-int",
            0x8d: "int-to-byte", 0x8e: "int-to-char",
            0x8f: "int-to-short",
        }
        for op, name in expected.items():
            u = UnOp(op, MagicMock())
            u.fetch()
            assert u.prefix == name

    def test_fetch_invalid(self):
        with pytest.raises(OpCodeNotFoundError):
            UnOp(0x99, MagicMock()).fetch()

    def test_execute_neg_int(self):
        u = UnOp(0x7b, MagicMock())
        u.fetch()
        u.vA, u.vB = 0, 1
        regs = [0, 5]
        u.execute(MagicMock(), regs)
        assert regs[0] == -5

    def test_execute_neg_int_type_error_gives_zero(self):
        u = UnOp(0x7b, MagicMock())
        u.fetch()
        u.vA, u.vB = 0, 1
        regs = [0, None]
        u.execute(MagicMock(), regs)
        assert regs[0] == 0

    def test_execute_not_int(self):
        u = UnOp(0x7c, MagicMock())
        u.fetch()
        u.vA, u.vB = 0, 1
        regs = [0, 0xFF]
        u.execute(MagicMock(), regs)
        assert regs[0] == ~0xFF

    def test_execute_neg_long(self):
        u = UnOp(0x7d, MagicMock())
        u.fetch()
        u.vA, u.vB = 0, 2
        regs = [0, 0, 3, 4]
        u.execute(MagicMock(), regs)
        assert regs[0] == -3
        assert regs[1] == -4

    def test_execute_int_to_long_zeroes_upper(self):
        u = UnOp(0x81, MagicMock())
        u.fetch()
        u.vA, u.vB = 0, 2
        regs = [0, 0, 42]
        u.execute(MagicMock(), regs)
        assert regs[0] == 42
        assert regs[1] == 0

    def test_execute_int_to_byte_positive(self):
        u = UnOp(0x8d, MagicMock())
        u.fetch()
        u.vA, u.vB = 0, 1
        regs = [0, 0x42]
        u.execute(MagicMock(), regs)
        assert regs[0] == 0x42

    def test_execute_int_to_byte_sign_extends(self):
        u = UnOp(0x8d, MagicMock())
        u.fetch()
        u.vA, u.vB = 0, 1
        regs = [0, 0x80]
        u.execute(MagicMock(), regs)
        assert regs[0] == 0x80 - 0xFF - 1

    def test_execute_int_to_short_positive(self):
        u = UnOp(0x8f, MagicMock())
        u.fetch()
        u.vA, u.vB = 0, 1
        regs = [0, 100]
        u.execute(MagicMock(), regs)
        assert regs[0] == 100

    def test_execute_int_to_short_sign_extends(self):
        u = UnOp(0x8f, MagicMock())
        u.fetch()
        u.vA, u.vB = 0, 1
        regs = [0, 0x8000]
        u.execute(MagicMock(), regs)
        assert regs[0] == 0x8000 - 0xFFFF - 1


# ──────────────────────────────────────────────
# BinOp
# ──────────────────────────────────────────────

class TestBinOp:
    def test_fetch_add_int(self):
        b = BinOp(0x90, MagicMock())
        b.fetch()
        assert b.prefix == "add-int"

    def test_fetch_sub_int(self):
        b = BinOp(0x91, MagicMock())
        b.fetch()
        assert b.prefix == "sub-int"

    def test_fetch_invalid(self):
        with pytest.raises(OpCodeNotFoundError):
            BinOp(0x01, MagicMock()).fetch()

    def test_execute_add_int(self):
        b = BinOp(0x90, MagicMock())
        b.fetch()
        b.vA, b.vB, b.vC = 0, 1, 2
        regs = [0, 3, 4]
        b.execute(MagicMock(), regs)
        assert regs[0] == 7

    def test_execute_mul_int(self):
        b = BinOp(0x92, MagicMock())
        b.fetch()
        b.vA, b.vB, b.vC = 0, 1, 2
        regs = [0, 6, 7]
        b.execute(MagicMock(), regs)
        assert regs[0] == 42

    def test_execute_div_zero(self):
        b = BinOp(0x93, MagicMock())
        b.fetch()
        b.vA, b.vB, b.vC = 0, 1, 2
        regs = [0, 10, 0]
        b.execute(MagicMock(), regs)
        assert regs[0] == 0


# ──────────────────────────────────────────────
# BinOp2Addr
# ──────────────────────────────────────────────

class TestBinOp2Addr:
    def test_fetch_add_int_2addr(self):
        b = BinOp2Addr(0xb0, MagicMock())
        b.fetch()
        assert "add" in b.prefix
        assert b.suffix == "2addr"

    def test_fetch_invalid(self):
        with pytest.raises(OpCodeNotFoundError):
            BinOp2Addr(0x01, MagicMock()).fetch()

    def test_execute_add_int_2addr(self):
        # vA op= vB: result stored back into vA
        b = BinOp2Addr(0xb0, MagicMock())
        b.fetch()
        b.vA, b.vB = 0, 1
        regs = [10, 5]
        b.execute(MagicMock(), regs)
        assert regs[0] == 15

    def test_execute_sub_int_2addr(self):
        b = BinOp2Addr(0xb1, MagicMock())  # sub-int/2addr
        b.fetch()
        b.vA, b.vB = 0, 1
        regs = [10, 3]
        b.execute(MagicMock(), regs)
        assert regs[0] == 7

    def test_execute_div_zero_2addr(self):
        b = BinOp2Addr(0xb3, MagicMock())  # div-int/2addr
        b.fetch()
        b.vA, b.vB = 0, 1
        regs = [10, 0]
        b.execute(MagicMock(), regs)
        assert regs[0] == 0


# ──────────────────────────────────────────────
# BinOpLit
# ──────────────────────────────────────────────

class TestBinOpLit:
    def test_fetch_lit16(self):
        b = BinOpLit(0xd0, MagicMock())
        b.fetch()
        assert b.suffix == "lit16"

    def test_fetch_lit8(self):
        b = BinOpLit(0xd8, MagicMock())
        b.fetch()
        assert b.suffix == "lit8"

    def test_fetch_invalid(self):
        with pytest.raises(OpCodeNotFoundError):
            BinOpLit(0x01, MagicMock()).fetch()

    def test_execute_add_lit8(self):
        b = BinOpLit(0xd8, MagicMock())
        b.fetch()
        b.vA, b.vB, b.vC = 0, 1, 5
        regs = [0, 10]
        b.execute(MagicMock(), regs)
        assert regs[0] == 15

    def test_execute_mul_lit8(self):
        b = BinOpLit(0xda, MagicMock())
        b.fetch()
        b.vA, b.vB, b.vC = 0, 1, 3
        regs = [0, 7]
        b.execute(MagicMock(), regs)
        assert regs[0] == 21

    def test_execute_rsub_reverses_operands(self):
        b = BinOpLit(0xd1, MagicMock())  # rsub-int/lit16
        b.fetch()
        b.vA, b.vB, b.vC = 0, 1, 10
        regs = [0, 3]  # 10 - 3 = 7
        b.execute(MagicMock(), regs)
        assert regs[0] == 7


# ──────────────────────────────────────────────
# InvokePolymorphic
# ──────────────────────────────────────────────

class TestInvokePolymorphic:
    def test_fetch_polymorphic(self):
        ip = InvokePolymorphic(0xfa, MagicMock())
        ip.fetch()
        assert ip.prefix == "invoke-polymorphic"
        assert ip.suffix == ""

    def test_fetch_range(self):
        ip = InvokePolymorphic(0xfb, MagicMock())
        ip.fetch()
        assert ip.suffix == "range"

    def test_fetch_invalid(self):
        with pytest.raises(OpCodeNotFoundError):
            InvokePolymorphic(0x01, MagicMock()).fetch()

    def test_execute_sets_method_instr_values(self):
        ip = InvokePolymorphic(0xfa, MagicMock())
        ip.fetch()
        ip.vA, ip.vB, ip.vC, ip.vH = 2, 5, 0, 3
        mem = _mem()
        mem.dex.lookup_method.return_value = "poly_method"
        mem.dex.proto_ids[3].shorty_desc = "VI"
        ip.execute(mem, _regs())
        assert mem.method_instr_values['method_ref'] == "poly_method"
        assert mem.method_instr_values['is_external_call'] is True
        assert mem.method_instr_values['params'] == [0, 1]


# ──────────────────────────────────────────────
# InvokeCustom
# ──────────────────────────────────────────────

class TestInvokeCustom:
    def test_fetch_custom(self):
        ic = InvokeCustom(0xfc, MagicMock())
        ic.fetch()
        assert ic.prefix == "invoke-custom"
        assert ic.suffix == ""

    def test_fetch_range(self):
        ic = InvokeCustom(0xfd, MagicMock())
        ic.fetch()
        assert ic.suffix == "range"

    def test_fetch_invalid(self):
        with pytest.raises(OpCodeNotFoundError):
            InvokeCustom(0x01, MagicMock()).fetch()


# ──────────────────────────────────────────────
# ConstMethod
# ──────────────────────────────────────────────

class TestConstMethod:
    def test_fetch_handle(self):
        cm = ConstMethod(0xfe, MagicMock())
        cm.fetch()
        assert cm.prefix == "const-method-handle"

    def test_fetch_type(self):
        cm = ConstMethod(0xff, MagicMock())
        cm.fetch()
        assert cm.prefix == "const-method-type"

    def test_fetch_invalid(self):
        with pytest.raises(OpCodeNotFoundError):
            ConstMethod(0x01, MagicMock()).fetch()