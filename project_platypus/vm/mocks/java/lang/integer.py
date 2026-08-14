from vm.mock_handler import register_mock


@register_mock
def valueOf(args, state_data):
    return int(args[0])

@register_mock
def intValue(args, state_data):
    return int(args[0])

