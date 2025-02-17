import wolfssl
from wolfssl.exceptions import SSLError
import socket
from wolfssl._ffi import ffi
from wolfssl._ffi import lib
bind_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
context = wolfssl.SSLContext(wolfssl.PROTOCOL_TLSv1_2)
secure_socket = context.wrap_socket(bind_socket, do_handshake_on_connect=False)
secure_socket.connect(('www.example.com', 443))
try:
    secure_socket.do_handshake(True)
except SSLError as se:
    if se.args and len(se.args) > 0 and se.args[0].startswith('do_handshake failed with error -313'):
        print('Cipher not supported')

cipher_list = wolfssl.get_ciphers_iana()
print(cipher_list)

cipher = secure_socket.get_current_cipher()
name = cipher.get_name_iana()
print(name)
s = secure_socket.get_cipher_name()
print(s)