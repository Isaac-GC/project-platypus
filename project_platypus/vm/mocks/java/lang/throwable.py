from vm.mock_handler import register_mock


@register_mock
def getStackTrace(args, state_data, vm):
    st = []
    if (args and args[0] == "CURRENT_THREAD") or ('CURRENT_THREAD' in state_data['current_registers'] ):
        st.append({"class_name": "java.lang.Thread", "method_name": "getStackTrace"})
        for mthd in vm.call_stack[::-1]:
            st.append(
                {
                    "class_name": mthd.clazz_name[1:-1].replace("/","."),
                    "method_name": mthd.method_name
                }
            )
    else:
        st.append({"class_name": args[0]})

    return st


@register_mock
def setStackTrace(args, state_data):
    return