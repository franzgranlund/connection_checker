# MIT License
# Copyright (c) 2026 Franz Granlund
# See LICENSE file in the project root for full license information.

import re
import socket


def matches_expect(value, expect, expect_regex):
    if expect is None:
        return True
    if expect_regex:
        return re.search(str(expect), value) is not None
    return str(expect) in value


def read_exact(sock, total, timeout):
    sock.settimeout(timeout)
    data = b""
    while len(data) < total:
        chunk = sock.recv(total - len(data))
        if not chunk:
            break
        data += chunk
    return data


def read_available(sock, max_bytes, timeout):
    sock.settimeout(timeout)
    try:
        return sock.recv(max_bytes)
    except socket.timeout:
        return b""
