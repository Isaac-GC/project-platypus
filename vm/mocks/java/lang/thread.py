from vm.mock_handler import register_mock


@register_mock
def currentThread(args, state_data):
    return "CURRENT_THREAD"

@register_mock
def getStackTrace(args, state_data, vm):
    st = []
    if args[0] == "CURRENT_THREAD":
        st.append({"class_name": "java.lang.Thread", "method_name": "getStackTrace"})
        for mthd in vm.call_stack[::-1]:
            st.append(
                {
                    "class_name": mthd.class_name[1:-1].replace("/","."),
                    "method_name": mthd.method_name
                }
            )

    return st