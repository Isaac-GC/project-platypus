"""
Tests for dex/clazz.py - parse_access_flags helper function.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from dex.clazz import parse_access_flags
from dex.access_flags import Class_AccessFlags


class TestParseAccessFlags:
    def test_single_flag_public(self):
        result = parse_access_flags(0x1)
        assert Class_AccessFlags.PUBLIC in result

    def test_multiple_flags(self):
        # PUBLIC | STATIC = 0x9
        result = parse_access_flags(0x9)
        assert Class_AccessFlags.PUBLIC in result
        assert Class_AccessFlags.STATIC in result

    def test_zero_returns_empty(self):
        result = parse_access_flags(0)
        assert result == []

    def test_none_input_returns_empty(self):
        result = parse_access_flags(None)
        assert result == []

    def test_non_int_input_returns_empty(self):
        result = parse_access_flags("not_an_int")
        assert result == []

    def test_all_flags_combined(self):
        # All valid Class_AccessFlags combined
        combined = 0
        for flag in Class_AccessFlags:
            combined |= flag.value
        result = parse_access_flags(combined)
        for flag in Class_AccessFlags:
            assert flag in result

    def test_abstract_flag(self):
        result = parse_access_flags(Class_AccessFlags.ABSTRACT.value)
        assert Class_AccessFlags.ABSTRACT in result

    def test_interface_and_abstract(self):
        combined = Class_AccessFlags.INTERFACE.value | Class_AccessFlags.ABSTRACT.value
        result = parse_access_flags(combined)
        assert Class_AccessFlags.INTERFACE in result
        assert Class_AccessFlags.ABSTRACT in result


"""
Tests for dex/vlq_base128_le.py - VLQ base-128 little-endian encoding.
"""
import io
from kaitaistruct import KaitaiStream
from dex.vlq_base128_le import VlqBase128Le


class TestVlqBase128Le:
    def _parse(self, data: bytes) -> int:
        stream = KaitaiStream(io.BytesIO(data))
        vlq = VlqBase128Le(stream)
        return vlq.value

    def test_single_byte_zero(self):
        assert self._parse(b'\x00') == 0

    def test_single_byte_one(self):
        assert self._parse(b'\x01') == 1

    def test_single_byte_max_no_continuation(self):
        # 0x7F = 0111 1111 → has_next=False, value=127
        assert self._parse(b'\x7f') == 127

    def test_two_byte_value(self):
        # 0x80 0x01 → first byte has continuation; value = 0 + (1 << 7) = 128
        assert self._parse(b'\x80\x01') == 128

    def test_three_byte_value(self):
        # 0x80 0x80 0x01 → 0 + (0 << 7) + (1 << 14) = 16384
        assert self._parse(b'\x80\x80\x01') == 16384

    def test_len_property(self):
        stream = KaitaiStream(io.BytesIO(b'\x80\x01'))
        vlq = VlqBase128Le(stream)
        assert vlq.len == 2

    def test_single_group_len(self):
        stream = KaitaiStream(io.BytesIO(b'\x05'))
        vlq = VlqBase128Le(stream)
        assert vlq.len == 1

    def test_group_has_next_false_for_low_byte(self):
        stream = KaitaiStream(io.BytesIO(b'\x05'))
        vlq = VlqBase128Le(stream)
        assert vlq.groups[0].has_next is False

    def test_group_has_next_true_for_high_byte(self):
        stream = KaitaiStream(io.BytesIO(b'\x80\x01'))
        vlq = VlqBase128Le(stream)
        assert vlq.groups[0].has_next is True
        assert vlq.groups[1].has_next is False

    def test_group_value_extraction(self):
        # 0x85 = 1000 0101; has_next=True, value = 0101 = 5
        stream = KaitaiStream(io.BytesIO(b'\x85\x01'))
        vlq = VlqBase128Le(stream)
        assert vlq.groups[0].value == 5
        assert vlq.groups[1].value == 1
        assert vlq.value == 5 + (1 << 7)  # = 133
