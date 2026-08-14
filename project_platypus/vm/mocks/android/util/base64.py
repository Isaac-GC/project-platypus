from base64 import b64decode, urlsafe_b64decode

from vm.mock_handler import register_mock


@register_mock
def decode(args, state_data):
    # Add missing padding to appease python
    match args[0]:
        case list(): args[0] += [61] * ( -len(args[0]) % 4)
        case _: args[0] += '=' * ( -len(args[0]) % 4)

    # Sanitize input through turning everything into bytes
    try:
        if len(args) == 1 or args[1] == 0:
            try:
                return list(b64decode(bytes(args[0])))
            except:
                return list(b64decode(args[0]))
        else:
            return list(urlsafe_b64decode(bytes(args[0])))

    except:
        return list(b64decode("".join([chr(x) for x in args[0]])))