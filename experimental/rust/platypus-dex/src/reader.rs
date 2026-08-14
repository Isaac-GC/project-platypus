/// A cursor-based binary reader over a DEX file byte buffer.
/// Replaces kaitaistruct's KaitaiStream + the VlqBase128Le module.

use std::io::{self, Cursor, Read, Seek, SeekFrom};

pub struct DexReader {
    cursor: Cursor<Vec<u8>>,
}

impl DexReader {
    pub fn new(data: Vec<u8>) -> Self {
        DexReader { cursor: Cursor::new(data) }
    }

    pub fn from_file(path: &str) -> io::Result<Self> {
        let data = std::fs::read(path)?;
        Ok(DexReader::new(data))
    }

    pub fn pos(&self) -> u64 {
        self.cursor.position()
    }

    pub fn seek(&mut self, pos: u64) -> io::Result<()> {
        self.cursor.seek(SeekFrom::Start(pos))?;
        Ok(())
    }

    pub fn data(&self) -> &[u8] {
        self.cursor.get_ref()
    }

    /// Consume the reader and return the underlying byte buffer.
    pub fn into_inner(self) -> Vec<u8> {
        self.cursor.into_inner()
    }

    pub fn len(&self) -> usize {
        self.cursor.get_ref().len()
    }

    // ── primitive reads ──────────────────────────────────────────────────────

    pub fn read_u8(&mut self) -> io::Result<u8> {
        let mut buf = [0u8; 1];
        self.cursor.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    pub fn read_i8(&mut self) -> io::Result<i8> {
        Ok(self.read_u8()? as i8)
    }

    pub fn read_u16_le(&mut self) -> io::Result<u16> {
        let mut buf = [0u8; 2];
        self.cursor.read_exact(&mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }

    pub fn read_i16_le(&mut self) -> io::Result<i16> {
        let mut buf = [0u8; 2];
        self.cursor.read_exact(&mut buf)?;
        Ok(i16::from_le_bytes(buf))
    }

    pub fn read_u32_le(&mut self) -> io::Result<u32> {
        let mut buf = [0u8; 4];
        self.cursor.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    pub fn read_i32_le(&mut self) -> io::Result<i32> {
        let mut buf = [0u8; 4];
        self.cursor.read_exact(&mut buf)?;
        Ok(i32::from_le_bytes(buf))
    }

    pub fn read_u64_le(&mut self) -> io::Result<u64> {
        let mut buf = [0u8; 8];
        self.cursor.read_exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    pub fn read_i64_le(&mut self) -> io::Result<i64> {
        let mut buf = [0u8; 8];
        self.cursor.read_exact(&mut buf)?;
        Ok(i64::from_le_bytes(buf))
    }

    pub fn read_f32_le(&mut self) -> io::Result<f32> {
        let raw = self.read_u32_le()?;
        Ok(f32::from_bits(raw))
    }

    pub fn read_f64_le(&mut self) -> io::Result<f64> {
        let raw = self.read_u64_le()?;
        Ok(f64::from_bits(raw))
    }

    pub fn read_bytes(&mut self, n: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; n];
        self.cursor.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Read two 4-bit nibbles from one byte: returns (lo, hi).
    pub fn read_nibbles(&mut self) -> io::Result<(u8, u8)> {
        let b = self.read_u8()?;
        Ok((b & 0x0F, b >> 4))
    }

    // ── ULEB128 / VLQ Base-128 LE ────────────────────────────────────────────
    // Corresponds to vlq_base128_le.py

    /// Decode an unsigned LEB128 value, returning the decoded integer.
    pub fn read_uleb128(&mut self) -> io::Result<u64> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = self.read_u8()?;
            result |= ((byte & 0x7F) as u64) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift >= 64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ULEB128 too large",
                ));
            }
        }
        Ok(result)
    }

    /// Decode a signed LEB128 (SLEB128) value.
    pub fn read_sleb128(&mut self) -> io::Result<i64> {
        let mut result: i64 = 0;
        let mut shift = 0u32;
        let mut byte;
        loop {
            byte = self.read_u8()?;
            result |= ((byte & 0x7F) as i64) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
            if shift >= 64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SLEB128 too large",
                ));
            }
        }
        // Sign extend if needed
        if shift < 64 && (byte & 0x40) != 0 {
            result |= !0i64 << shift;
        }
        Ok(result)
    }

    // ── Null-terminated MUTF-8 string ────────────────────────────────────────

    /// Read bytes until null terminator; decode as UTF-8 (replacing invalid sequences).
    /// This corresponds to the StringDataItem._read() in dex.py.
    pub fn read_mutf8_string(&mut self) -> io::Result<String> {
        let mut raw: Vec<u8> = Vec::new();
        loop {
            let b = self.read_u8()?;
            if b == 0 {
                break;
            }
            raw.push(b);
        }
        Ok(String::from_utf8_lossy(&raw).into_owned())
    }

    // ── Seek-save helpers ────────────────────────────────────────────────────

    /// Run `f` at `offset`, then restore the original position.
    pub fn at<T, F>(&mut self, offset: u64, f: F) -> io::Result<T>
    where
        F: FnOnce(&mut Self) -> io::Result<T>,
    {
        let saved = self.pos();
        self.seek(offset)?;
        let result = f(self)?;
        self.seek(saved)?;
        Ok(result)
    }
}
