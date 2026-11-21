"""Verify an accepted Unix stream's kernel peer UID without reading bytes."""
import os
import socket
import struct
import sys


def peer_uid(sock):
    fmt = "iII"
    raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize(fmt))
    pid, uid, _ = struct.unpack(fmt, raw)
    return uid if pid > 0 else None


if sys.argv[1:] == ["probe"]:
    left, right = socket.socketpair()
    with left, right:
        sys.exit(0 if peer_uid(left) == os.getuid() else 1)

if len(sys.argv) not in (3, 4) or sys.argv[1] != "peer" or not all(value.isdecimal() for value in sys.argv[2:]):
    sys.exit(1)
with socket.socket(fileno=3) as sock:
    if sock.family != socket.AF_UNIX or sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM:
        sys.exit(1)
    uid = peer_uid(sock)
    sys.exit(0 if uid in {int(value) for value in sys.argv[2:]} else 1)
