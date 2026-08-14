from vm.mock_handler import register_mock


@register_mock
def _0init0(args, state_data):
    args[0] = []

@register_mock
def write(args, state_data):
    args[0].append(args[1])

@register_mock
def toByteArray(args, state_data):
    return args[0]