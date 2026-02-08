# MIT License
# Copyright (c) 2026 Franz Granlund
# See LICENSE file in the project root for full license information.

"""MySQL handshake check.

Config keys:
- host (str, required)
- port (int, required)
- timeout (float, optional, seconds, default 5)
- expect_protocol_version (int, optional, default 10)
- expect_server_version (str, optional; substring or regex)
- expect_server_version_regex (bool, optional, default False)

Example:
cfg = {
    "host": "127.0.0.1",
    "port": 3306,
    "expect_server_version": "8.0",
}
"""

import socket

from .util import matches_expect, read_exact


def check_mysql(cfg):
    host = cfg.get("host")
    port = int(cfg.get("port", 0))
    timeout = float(cfg.get("timeout", 5))
    expect_protocol = int(cfg.get("expect_protocol_version", 10))
    expect_server_version = cfg.get("expect_server_version")
    expect_server_version_regex = bool(cfg.get("expect_server_version_regex", False))
    if not host or not port:
        return False, "mysql requires host and port"
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            header = read_exact(sock, 4, timeout)
            if len(header) < 4:
                return False, "mysql handshake header incomplete"
            payload_len = header[0] | (header[1] << 8) | (header[2] << 16)
            payload = read_exact(sock, payload_len, timeout)
            if len(payload) < 2:
                return False, "mysql handshake payload incomplete"
            protocol_version = payload[0]
            if protocol_version != expect_protocol:
                return (
                    False,
                    f"mysql protocol {protocol_version} != {expect_protocol}",
                )
            server_version = payload[1:].split(b"\x00", 1)[0].decode(
                "utf-8", errors="replace"
            )
            if expect_server_version is not None:
                if not matches_expect(
                    server_version,
                    expect_server_version,
                    expect_server_version_regex,
                ):
                    return False, "mysql server version mismatch"
            return True, f"mysql handshake ok: {server_version}"
    except OSError as exc:
        return False, f"mysql failed: {exc}"
