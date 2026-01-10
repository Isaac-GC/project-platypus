from typing import Tuple


class DataInputStream:
    def __init__(self, data: bytes, endianness = 'big'):
        self.data: bytes = data
        self.curr_pos = 0
        self.endianness = endianness

        # working arrays initialized on demand by readUTF
        self.byte_arr: bytes # Should be no longer than 80 bytes
        self.char_arr: str # Should be no longer than 80 chars

    def read(self, offset: int = 0, length: int = 0) -> Tuple[int, bytes]:
        if length > 0:
            buffered_data = self.data[offset:offset+length]
        else:
            buffered_data = self.data[offset:]
        return len(buffered_data), buffered_data

    def skip_bytes(self, num_bytes: int):
        if (num_bytes + self.curr_pos) < len(self.data):
            self.curr_pos += num_bytes
        else:
            self.curr_pos = len(self.data) - 1 # end of file

    def read_one(self) -> int | None:
        if self.curr_pos < len(self.data):
            b = self.data[self.curr_pos]
            self.curr_pos += 1
            return b
        return None

    def read_multiple(self, num_bytes: int):
        if (self.curr_pos + num_bytes) < len(self.data):
            b = self.data[self.curr_pos:self.curr_pos + num_bytes]
            self.curr_pos += num_bytes
            return b
        return None

    def read_boolean(self) -> bool:
        ch = self.read_one()
        return ch != 0

    def read_byte(self):
        return self.read_one().to_bytes(1, byteorder=self.endianness)

    def read_unsigned_byte(self):
        self.read_one()

    def read_short(self):
        buf = self.read_multiple(2)
        if self.endianness == 'big':
            return buf[0] << 8 | buf[1] & 0xFF
        else:
            return buf[1] << 8 | buf[0] & 0xFF

    def read_unsigned_short(self):
        return self.read_short() & 0xFFFF

    def read_char(self):
        return chr(self.read_short())

    def read_int(self):
        buf = self.read_multiple(4)
        if self.endianness == 'big':
            return (( (buf[3] & 0xFF) << 24) |
                      (buf[2] & 0xFF) << 16  |
                      (buf[1] & 0xFF) << 8  |
                      (buf[0] & 0xFF  << 0))
        else:
            return (( (buf[3] & 0xFF) <<  0) |
                      (buf[2] & 0xFF) <<  8  |
                      (buf[1] & 0xFF) << 16  |
                      (buf[0] & 0xFF  << 24 ))

    def read_long(self):
        buf = self.read_multiple(8)
        return ( (buf[0] << 56) +
                ((buf[1] & 255) << 48) +
                ((buf[2] & 255) << 40) +
                ((buf[3] & 255) << 32) +
                ((buf[4] & 255) << 24) +
                ((buf[5] & 255) << 16) +
                ((buf[6] & 255) << 8) +
                ((buf[7] & 255) << 0) )

    def read_float(self):
        buf = self.read_int()
