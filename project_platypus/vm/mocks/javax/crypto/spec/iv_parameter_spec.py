from vm.mock_handler import register_mock


@register_mock
def _0init0(args, state_data):
    state_data['iv_parameter_spec'] = args[1]