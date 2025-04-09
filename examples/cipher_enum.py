import wolfssl
from wolfssl.exceptions import SSLError
import socket
import ssl

import wolfssl.utils

def get_supported_tls_ciphers_wolfssl(host, port, protocol):
    wolfssl.WolfSSL.enable_debug()
    wolfssl.SSLContext(protocol)
    cipher_list = wolfssl.get_ciphers()

    supported_ciphers = set()
    
    for cipher in cipher_list:
        test_context = wolfssl.SSLContext(protocol)
        test_context.verify_mode = wolfssl.CERT_NONE
        test_context.check_hostname = False
        test_context.use_secure_renegotiation()
        test_context.use_session_ticket()
        test_context.set_ciphers(cipher)

        bind_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM,0)
        ssock = test_context.wrap_socket(bind_socket)
        try:
            ssock.connect((host, port))
            current_cipher = ssock.get_current_cipher()
            supported_ciphers.add(current_cipher.get_name())

        except SSLError as se:
            if se.args and len(se.args) > 0 and se.args[0].startswith('do_handshake failed with error -313'):
                pass
            else:
                ValueError(f"error testing cipher {cipher}: {se}")

    return supported_ciphers

def get_supported_tls_ciphers_openssl(host, port, protocol, force_tls_v13=False):
    context = ssl.SSLContext(protocol)
    if protocol == ssl.PROTOCOL_TLS_CLIENT and force_tls_v13:
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3

    supported_ciphers = set()

    for cipher in context.get_ciphers():
        try:
            test_context = ssl.SSLContext(protocol)
            if protocol == ssl.PROTOCOL_TLS_CLIENT and force_tls_v13:
                test_context.minimum_version = ssl.TLSVersion.TLSv1_3
                test_context.maximum_version = ssl.TLSVersion.TLSv1_3
            test_context.set_ciphers(cipher['name'])
            test_context.check_hostname = False
            test_context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port)) as sock:
                with test_context.wrap_socket(sock, server_hostname=host) as ssock:
                    negotiated_cipher = ssock.cipher()
                    if negotiated_cipher and negotiated_cipher[0] == cipher['name']:
                        supported_ciphers.add(cipher['name'])
        except ssl.SSLError as e:
            continue  # Cipher not supported by the server
        except Exception as e:
            ValueError(f"error testing cipher {cipher['name']}: {e}")
    return supported_ciphers


print(get_supported_tls_ciphers_wolfssl("www.example.org", 443, wolfssl.PROTOCOL_TLSv1_2))

print(ssl.OPENSSL_VERSION)
context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_CLIENT)
context.maximum_version = ssl.TLSVersion.TLSv1_1
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

sock = socket.create_connection(("www.example.com", 443))
session = context.wrap_socket(sock)
print(session.version())
session.sendall(b'GET / HTTP/2\n\n')
b= session.recv(1024)
print(b)
print(get_supported_tls_ciphers_openssl("www.example.org", 443, ssl, force_tls_v13=False))