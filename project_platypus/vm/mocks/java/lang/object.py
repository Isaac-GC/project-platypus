from vm.mock_handler import register_mock


@register_mock
def hashCode(args, state_data):
    h = 0
    for c in args[0]:
        h = int((((31 * h + ord(c)) ^ 0x80000000) & 0xFFFFFFFF) - 0x80000000)

    return h