
# Sourced referenced from: https://android.googlesource.com/platform/libcore/+/9edf43dfcc35c761d97eb9156ac4254152ddbc55/dex/src/main/java/com/android/dex/Mutf8.java

class ByteInput:
    def __init__(self, raw_bytes):
        self.bytes = raw_bytes
        self.pos = 0

    def read_byte(self):
        if self.pos >= len(self.bytes):
            print(f"num bytes: {len(self.bytes)}, pos: {self.pos}, content: {self.bytes}")
        b = self.bytes[self.pos]
        self.pos += 1
        return b


class Mutf8String:
    # Endianness should almost always be little... (especially for dex files)
    def __init__(self, raw_bytes: bytes, endianness: str = "little"):
        self.bytes_in = ByteInput(raw_bytes)
        self.endianness: str = endianness

    def set_endianness(self, endianness):
        self.endianness = endianness

    def get_endianness(self):
        return self.endianness

    def decode(self):
        s = 0
        out = []

        if self.endianness not in ["little", "big"]:
            return None

        while self.bytes_in.pos < len(self.bytes_in.bytes):
            a = self.bytes_in.read_byte() & 0xFF
            if a == '\x00':
                print(f"[+] Completed: {''.join(out)}")
                return "".join(out)

            out.append(chr(a))
            if a < 0x80:
                s += 1

            elif (a & 0xe0) == 0xc0:
                b = self.bytes_in.read_byte() & 0xFF
                if (b & 0xc0) != 0x80:
                    raise UTFDataFormatException("Bad second byte")

                out.append(chr( ((a & 0x1f) << 6) | (b & 0x3f)))
                s += 1

            elif (a & 0xf0) == 0xe0:
                b = self.bytes_in.read_byte() & 0xFF
                c = self.bytes_in.read_byte() & 0xFF

                if ((b & 0xC0) != 0x80) or ((c & 0xC0) != 0x80):
                    raise UTFDataFormatException("Bad second or third byte")

                out.append(chr((((a & 0x0F) << 12) | ((b & 0x3F) << 6) | (c & 0x3F))))

            else:
                print(f"Error Bytes: {self.bytes_in.bytes}")
                print("".join(out))
                # raise UTFDataFormatException("Bad byte")

        print(f"[+] Completed: {''.join(out)}")
        return "".join(out)


class UTFDataFormatException(Exception):
    def __init__(self, message="MUTF-8 decoding error"):
        super().__init__(message)