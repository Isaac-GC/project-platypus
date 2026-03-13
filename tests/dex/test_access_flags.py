"""
Tests for dex/access_flags.py - access flag enumerations.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from dex.access_flags import Method_AccessFlags, Class_AccessFlags, Field_AccessFlags


class TestMethodAccessFlags:
    def test_public_value(self):
        assert Method_AccessFlags.PUBLIC.value == 0x1

    def test_private_value(self):
        assert Method_AccessFlags.PRIVATE.value == 0x2

    def test_protected_value(self):
        assert Method_AccessFlags.PROTECTED.value == 0x4

    def test_static_value(self):
        assert Method_AccessFlags.STATIC.value == 0x8

    def test_final_value(self):
        assert Method_AccessFlags.FINAL.value == 0x10

    def test_constructor_value(self):
        assert Method_AccessFlags.CONSTRUCTOR.value == 0x10000

    def test_all_flags_are_unique(self):
        values = [f.value for f in Method_AccessFlags]
        assert len(values) == len(set(values))

    def test_flags_are_power_of_two(self):
        for flag in Method_AccessFlags:
            assert flag.value & (flag.value - 1) == 0, f"{flag.name} is not a power of 2"

    def test_flag_combination_bitmask(self):
        # Public + Static = 0x9
        combined = Method_AccessFlags.PUBLIC.value | Method_AccessFlags.STATIC.value
        assert combined == 0x9
        assert combined & Method_AccessFlags.PUBLIC.value
        assert combined & Method_AccessFlags.STATIC.value
        assert not (combined & Method_AccessFlags.PRIVATE.value)


class TestClassAccessFlags:
    def test_public_value(self):
        assert Class_AccessFlags.PUBLIC.value == 0x1

    def test_interface_value(self):
        assert Class_AccessFlags.INTERFACE.value == 0x0200

    def test_abstract_value(self):
        assert Class_AccessFlags.ABSTRACT.value == 0x0400

    def test_enum_value(self):
        assert Class_AccessFlags.ENUM.value == 0x4000

    def test_all_flags_unique(self):
        values = [f.value for f in Class_AccessFlags]
        assert len(values) == len(set(values))


class TestFieldAccessFlags:
    def test_public_value(self):
        assert Field_AccessFlags.PUBLIC.value == 0x1

    def test_volatile_value(self):
        assert Field_AccessFlags.VOLATILE.value == 0x40

    def test_synthetic_value(self):
        assert Field_AccessFlags.SYNTHETIC.value == 0x1000

    def test_all_flags_unique(self):
        values = [f.value for f in Field_AccessFlags]
        assert len(values) == len(set(values))

    def test_flag_detection_from_int(self):
        # Simulating how parse_access_flags works
        raw = Field_AccessFlags.PUBLIC.value | Field_AccessFlags.STATIC.value | Field_AccessFlags.FINAL.value
        found = [f for f in Field_AccessFlags if f.value & raw]
        assert Field_AccessFlags.PUBLIC in found
        assert Field_AccessFlags.STATIC in found
        assert Field_AccessFlags.FINAL in found
        assert Field_AccessFlags.PRIVATE not in found
