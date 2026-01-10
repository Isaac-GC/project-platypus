

MAGIC_BYTES = 0xCAFEBABE

class ClassParser:
    def __init__(self, class_bytes: bytes):
        self.class_bytes: bytes = class_bytes

    def parse(self):
        pass


    def read_id(self):
        magic_bytes: bytes = self.class_bytes[0:4]
        if magic_bytes == MAGIC_BYTES.to_bytes(4, 'big'):
            return True
        return False

    def read_version(self):
        minor = int.from_bytes(self.class_bytes[4:6], 'big')
        major = int.from_bytes(self.class_bytes[6:8], 'big')

    def read_constant_pool(self):
        constant_pool_bytes: bytes = self.class_bytes[8:12]








