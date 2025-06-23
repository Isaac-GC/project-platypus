from vm.mock_handler import register_mock


@register_mock
def isEmpty(args, state_data):
    try:
        return args[0] is None or len(args[0]) == 0
    except Exception:
        return 0
