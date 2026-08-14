from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from vm.mock_handler import register_mock



@register_mock
def getInstance(args, state_data):
    match args[0]:
        case b'AES/CBC/PKCS5Padding':
            state_data['cipher_instance'] = 'aes_cbc_pkcs5'


@register_mock
def doFinal(args, state_data):
    key = bytearray(state_data['secret_key_spec'])
    iv  = bytearray(state_data['iv_parameter_spec'])
    cipher_text = bytearray(args[1])

    cipher = None
    if state_data['cipher_instance']:
        match state_data['cipher_instance']:
            case 'aes_cbc_pkcs5':
                cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)

    decrypted = unpad(cipher.decrypt(cipher_text), AES.block_size)

    return decrypted
