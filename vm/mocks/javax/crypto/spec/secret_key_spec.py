from vm.mock_handler import register_mock


@register_mock
def _0init0(args, state_data):
    state_data['secret_key_spec'] = args[1]