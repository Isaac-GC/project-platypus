from vm.mock_handler import register_mock


@register_mock
def _0init0(args, state_data):
    args[0] = []

@register_mock
def size(args, state_data):
    return len(args[0])

@register_mock
def add(args, state_data):
    if not args[0]:
        args[0] = []
    args[0].append(args[1])


@register_mock
def get(args, state_data):
    return args[0][args[1]]