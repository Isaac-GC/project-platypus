from vm.mock_handler import register_mock


@register_mock
def hasNext(args, state_data):
    return False