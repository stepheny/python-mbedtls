#!/usr/bin/env python

import socket
import struct

from mbedtls.x509 import CRT
from mbedtls.tls import *
from mbedtls.tls import _enable_debug_output, _set_debug_level

with open("ca0.crt", "rt") as ca:
    ca0_crt = CRT.from_PEM(ca.read())

trust_store = TrustStore()
trust_store.add(ca0_crt)


conf = DTLSConfiguration(trust_store=trust_store, validate_certificates=False)

_enable_debug_output(conf)
_set_debug_level(1)

address = ("127.0.0.1", 4433)
host, port = address

ctx = ClientContext(conf)
cli = ctx.wrap_socket(
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP),
    server_hostname="localhost",
)

print(" .", "connect", address)
cli.connect(address)


def block(cb, *args, **kwargs):
    while True:
        try:
            result = cb(*args, **kwargs)
        except (WantReadError, WantWriteError):
            print(" .", cb.__name__)
        else:
            print(" .", "done", cb.__name__, result)
            return result


block(cli.do_handshake)
print(" .", "handshake", cli.negotiated_tls_version())

msg = b"hello"
for _ in range(1):
    nn = block(cli.send, msg)
    print(" .", "S", nn, len(msg))
    data, addr = block(cli.recvfrom, 4096)
    print(" .", "R", nn, data)
else:
    block(cli.send, b"\0")
    block(cli.recvfrom, 4096)

print(cli)
cli.close()
