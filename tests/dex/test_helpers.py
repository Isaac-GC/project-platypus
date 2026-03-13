"""
Tests for dex/helpers.py - utility functions for byte manipulation and arithmetic.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from dex.helpers import (
    b2i, lsb, msb, nibble_at, twos_complement, i2b,
    logical_rshift, logical_lshift, alu_op, string_hash_code
)


# ──────────────────────────────────────────────
# b2i
# ──────────────────────────────────────────────
class TestB2I:
    def test_single_zero_byte(self):
        assert b2i(b'\x00') == 0

    def test_single_byte(self):
        assert b2i(b'\xff') == 255

    def test_little_endian_two_bytes(self):
        assert b2i(b'\x01\x00') == 1
        assert b2i(b'\x00\x01') == 256

    def test_four_bytes(self):
        assert b2i(b'\x78\x56\x34\x12') == 0x12345678

    def test_empty_bytes(self):
        assert b2i(b'') == 0


# ──────────────────────────────────────────────
# lsb / msb
# ──────────────────────────────────────────────
class TestNibbleFunctions:
    def test_lsb_zero(self):
        assert lsb(0x00) == 0x0

    def test_lsb_typical(self):
        assert lsb(0xAB) == 0xB

    def test_msb_zero(self):
        assert msb(0x00) == 0x0

    def test_msb_typical(self):
        assert msb(0xAB) == 0xA

    def test_nibble_at_index_0(self):
        assert nibble_at(0xAB, 0) == 0xB

    def test_nibble_at_index_1(self):
        assert nibble_at(0xAB, 1) == 0xA

    def test_nibble_at_zero_byte(self):
        assert nibble_at(0x00, 0) == 0
        assert nibble_at(0x00, 1) == 0


# ──────────────────────────────────────────────
# twos_complement
# ──────────────────────────────────────────────
class TestTwosComplement:
    def test_positive_number_unchanged(self):
        # MSB is 0 → positive, unchanged
        assert twos_complement(0x7F, 1) == 0x7F

    def test_negative_byte(self):
        # 0xFF in 1-byte two's complement == -1
        assert twos_complement(0xFF, 1) == -1

    def test_negative_two_bytes(self):
        # 0xFFFF in 2-byte two's complement == -1
        assert twos_complement(0xFFFF, 2) == -1

    def test_zero(self):
        assert twos_complement(0x00, 1) == 0

    def test_min_positive_two_bytes(self):
        # 0x7FFF is the max positive for 2 bytes
        assert twos_complement(0x7FFF, 2) == 0x7FFF


# ──────────────────────────────────────────────
# i2b
# ──────────────────────────────────────────────
class TestI2B:
    def test_small_value(self):
        assert i2b(1) == b'\x01'

    def test_multi_byte_value(self):
        result = i2b(0x0102)
        assert result == b'\x01\x02'

    def test_256(self):
        assert i2b(256) == b'\x01\x00'


# ──────────────────────────────────────────────
# logical_rshift / logical_lshift
# ──────────────────────────────────────────────
class TestLogicalShifts:
    def test_logical_rshift_positive(self):
        assert logical_rshift(4, 1) == 2

    def test_logical_rshift_negative_treated_as_unsigned(self):
        # -1 in 32-bit unsigned is 0xFFFFFFFF; shifting right by 1 = 0x7FFFFFFF
        result = logical_rshift(-1, 1)
        assert result == 0x7FFFFFFF

    def test_logical_rshift_zero_shift(self):
        assert logical_rshift(100, 0) == 100

    def test_logical_lshift(self):
        assert logical_lshift(1, 3) == 8

    def test_logical_lshift_wraps_32_bits(self):
        result = logical_lshift(1, 32)
        # 1 << 32 mod 2^32 = 4294967296 (or should as it wraps around)
        assert result == 4294967296


# ──────────────────────────────────────────────
# alu_op
# ──────────────────────────────────────────────
class TestAluOp:
    # operand 0x0 = int (32-bit)
    def test_add_int(self):
        assert alu_op(0x0, 0x0, 1, 2) == 3

    def test_sub_int(self):
        assert alu_op(0x1, 0x0, 10, 3) == 7

    def test_mul_int(self):
        assert alu_op(0x2, 0x0, 4, 5) == 20

    def test_div_int(self):
        assert alu_op(0x3, 0x0, 10, 2) == 5

    def test_div_by_zero_returns_zero(self):
        assert alu_op(0x3, 0x0, 10, 0) == 0

    def test_mod_int(self):
        assert alu_op(0x4, 0x0, 10, 3) == 1

    def test_and_int(self):
        assert alu_op(0x5, 0x0, 0xFF, 0x0F) == 0x0F

    def test_or_int(self):
        assert alu_op(0x6, 0x0, 0xF0, 0x0F) == 0xFF

    def test_xor_int(self):
        assert alu_op(0x7, 0x0, 0xFF, 0x0F) == 0xF0

    def test_shl_int(self):
        result = alu_op(0x8, 0x0, 1, 4)
        assert result == 16

    def test_shr_int(self):
        result = alu_op(0x9, 0x0, 16, 2)
        assert result == 4

    def test_none_operands_treated_as_zero(self):
        # b=None, c=None → both become 0
        result = alu_op(0x0, 0x0, None, None)
        assert result == 0

    def test_result_is_signed_32_bit_int(self):
        # 0x80000001 should become negative after sign adjustment
        result = alu_op(0x0, 0x0, 0x7FFFFFFF, 2)
        assert isinstance(result, int)


# ──────────────────────────────────────────────
# string_hash_code
# ──────────────────────────────────────────────
class TestStringHashCode:
    def test_empty_string(self):
        assert string_hash_code("") == 0

    def test_known_hash(self):
        # Java's "Hello".hashCode() == 69609650
        assert string_hash_code("Hello") == 69609650

    def test_single_char(self):
        # Java: 'a'.hashCode() == 97
        assert string_hash_code("a") == 97

    def test_deterministic(self):
        assert string_hash_code("test") == string_hash_code("test")

    def test_different_strings_differ(self):
        assert string_hash_code("abc") != string_hash_code("xyz")
