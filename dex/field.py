from dex.access_flags import Field_AccessFlags
from dex.dex import Dex



def parse_access_flags(raw_access_flags):
    print(f"Starting aflag: {raw_access_flags}")
    parsed_access_flags = []
    for aflag in Field_AccessFlags:
        if raw_access_flags and isinstance(raw_access_flags, int):
            if aflag.value & raw_access_flags:
                parsed_access_flags.append(aflag)
                raw_access_flags -= aflag.value
                print(f"a_flags: {parsed_access_flags}, raw_flag: {raw_access_flags}")


class Field:
    def __init__(self, curr_idx: int, encoded_field: Dex.EncodedField, dex):
        self.encoded_field = encoded_field
        self.field_idx = curr_idx
        self.dex = dex
        self.fd = dex.fd

        self.access_flags = encoded_field.access_flags if type(encoded_field.access_flags) else parse_access_flags(encoded_field.access_flags)

        self.field_id_item: Dex.FieldIdItem = self.dex.dex.field_ids[self.field_idx]
        self.clazz_name = self.field_id_item.class_name
        self.type_name = self.field_id_item.type_name
        self.name = self.field_id_item.field_name
