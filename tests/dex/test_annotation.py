"""
Tests for dex/annotation.py - ValueFormats enum and encoded value parsing.
"""
import pytest
import sys
import os
import io
import struct
from unittest.mock import MagicMock, patch, PropertyMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from dex.annotation import ValueFormats, Annotation


class TestValueFormats:
    def test_byte_value(self):
        assert ValueFormats.BYTE.value == 0x00

    def test_short_value(self):
        assert ValueFormats.SHORT.value == 0x02

    def test_char_value(self):
        assert ValueFormats.CHAR.value == 0x03

    def test_int_value(self):
        assert ValueFormats.INT.value == 0x04

    def test_long_value(self):
        assert ValueFormats.LONG.value == 0x06

    def test_float_value(self):
        assert ValueFormats.FLOAT.value == 0x10

    def test_double_value(self):
        assert ValueFormats.DOUBLE.value == 0x11

    def test_string_value(self):
        assert ValueFormats.STRING.value == 0x17

    def test_type_value(self):
        assert ValueFormats.TYPE.value == 0x18

    def test_null_value(self):
        assert ValueFormats.NULL.value == 0x1E

    def test_boolean_value(self):
        assert ValueFormats.BOOLEAN.value == 0x1F

    def test_array_value(self):
        assert ValueFormats.ARRAY.value == 0x1C

    def test_annotation_value(self):
        assert ValueFormats.ANNOTATION.value == 0x1D

    def test_all_values_unique(self):
        values = [f.value for f in ValueFormats]
        assert len(values) == len(set(values))

    def test_enum_lookup_by_value(self):
        assert ValueFormats(0x00) == ValueFormats.BYTE
        assert ValueFormats(0x1F) == ValueFormats.BOOLEAN
        assert ValueFormats(0x17) == ValueFormats.STRING


class TestAnnotationParseEncodedValue:
    """Tests for Annotation.parse_encoded_value using a mocked cursor."""

    def _make_annotation(self, byte_data: bytes):
        """Build a minimal Annotation instance pointing at a BytesIO stream."""
        cursor = io.BytesIO(byte_data)

        dex_mock = MagicMock()
        dex_file_reference = MagicMock()
        dex_file_reference.dex = dex_mock

        # Bypass __init__ heavy lifting by patching internals
        annotation = object.__new__(Annotation)
        annotation.cursor = cursor
        annotation.dex = dex_mock
        return annotation

    def test_parse_null(self):
        # value_type = NULL (0x1E), value_arg = 0 → header byte = 0x1E
        ann = self._make_annotation(bytes([0x1E]))
        result = ann.parse_encoded_value()
        assert result is None

    def test_parse_boolean_true(self):
        # value_arg = 1 (bits 7-5) = 0x20, value_type = BOOLEAN (0x1F)
        # header = (1 << 5) | 0x1F = 0x3F
        ann = self._make_annotation(bytes([0x3F]))
        result = ann.parse_encoded_value()
        assert result is True

    def test_parse_boolean_false(self):
        # value_arg = 0, value_type = BOOLEAN (0x1F) → header = 0x1F
        ann = self._make_annotation(bytes([0x1F]))
        result = ann.parse_encoded_value()
        assert result is False

    def test_parse_byte_value(self):
        # value_type = BYTE (0x00), then 1 byte payload = 0x42
        ann = self._make_annotation(bytes([0x00, 0x42]))
        result = ann.parse_encoded_value()
        assert result == 0x42

    def test_parse_short_value(self):
        # value_type = SHORT (0x02), size = 0+1 = 1 byte
        # Header: value_arg=0 → size=1; value_type=0x02 → read 1 byte
        ann = self._make_annotation(bytes([0x02, 0x05]))
        result = ann.parse_encoded_value()
        assert result == 5

    def test_parse_float_value(self):
        # value_type = FLOAT (0x10), value_arg determines size
        # size = value_arg + 1, value_arg stored in top 3 bits
        # For a 4-byte float: value_arg = 3 → header = (3 << 5) | 0x10 = 0x70
        # Payload: little-endian float 1.0 = 0x3F800000
        raw_float = struct.pack('<f', 1.0)  # 4 bytes
        header = bytes([(3 << 5) | 0x10])
        ann = self._make_annotation(header + raw_float)
        result = ann.parse_encoded_value()
        assert result == pytest.approx(1.0, rel=1e-5)
