#!/usr/bin/env python

import datetime as dt
import faulthandler
import socket
import struct

import mbedtls.hash as hashlib
from mbedtls.pk import RSA, ECC
from mbedtls.x509 import BasicConstraints, CRT, CSR
from mbedtls.tls import *
from mbedtls.tls import _enable_debug_output, _set_debug_level

faulthandler.enable()

now = dt.datetime.utcnow()
digestmod = hashlib.sha256

ca0_key = RSA()
ca0_key.generate()
ca1_key = ECC()
ca1_key.generate()
ee0_key = ECC()
ee0_key.generate()

ca0_crt = CRT.selfsign(
    CSR.new(ca0_key, "CN=Trusted CA", digestmod()),
    ca0_key,
    not_before=now,
    not_after=now + dt.timedelta(days=90),
    serial_number=0x123456,
    basic_constraints=BasicConstraints(True, -1),
)
ca1_crt = ca0_crt.sign(
    CSR.new(ca1_key, "CN=Intermediate CA", digestmod()),
    ca0_key,
    not_before=now,
    not_after=now + dt.timedelta(days=90),
    serial_number=0x234567,
    basic_constraints=BasicConstraints(True, -1),
)
ee0_crt = ca1_crt.sign(
    CSR.new(ee0_key, "CN=End Entity", digestmod()),
    ca1_key,
    not_before=now,
    not_after=now + dt.timedelta(days=90),
    serial_number=0x345678,
)

with open("ca0.crt", "wt") as ca:
    ca.write(ca0_crt.to_PEM())

trust_store = TrustStore()
trust_store.add(CRT.from_DER(ca0_crt.to_DER()))

def block(cb, *args, **kwargs):
    while True:
        try:
            result = cb(*args, **kwargs)
        except (WantReadError, WantWriteError):
            print(" .", cb.__name__)
        else:
            print(" .", "done", cb.__name__, result)
            return result


cookie = DTLSCookie()
cookie.generate()
conf = DTLSConfiguration(
    trust_store=trust_store,
    certificate_chain=([ee0_crt, ca1_crt], ee0_key),
    validate_certificates=False,
    # cookie=cookie,
)

_enable_debug_output(conf)
_set_debug_level(1)

def echo_until(sock, end):
    print(" .", "accept")
    cli, cli_address = sock.accept()
    ctx._set_client_id(cli_address[0].encode("ascii"))
    print(" .", "accepted", cli, cli_address)

    cli.connect(cli_address)
    block(cli.do_handshake)
    print(" .", "handshake", cli.negotiated_tls_version())

    while True:
        data, addr = block(cli.recvfrom, 4096)
        print(" .", "R", data, addr)
        nn = block(cli.send, data)
        print(" .", "S", nn, len(data))
        if data == end:
            break

    print(" .", "done")
    print(cli)
    cli.close()

address = ("0.0.0.0", 4433)
host, port = address

ctx = ServerContext(conf)
srv = ctx.wrap_socket(
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
)

print(" .", "bind", srv, address)
srv.bind(address)

while True:
    print(" .", ">>>")
    echo_until(srv, b"\0")
    print(" .", "<<<")
