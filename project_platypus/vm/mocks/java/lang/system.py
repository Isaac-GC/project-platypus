from vm.mock_handler import register_mock


@register_mock
def arraycopy(args, state_data):
    args[2][args[3]:args[1]+args[4]] = args[0][args[1]:args[1]+args[4]]