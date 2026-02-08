"""Postgres startup/auth check.

Config keys:
- host (str, required)
- port (int, required)
- timeout (float, optional, seconds, default 5)
- user (str, optional, default "postgres")
- database (str, optional, default "postgres")
- expect_auth_ok (bool, optional, default False)

Example:
cfg = {
    "host": "127.0.0.1",
    "port": 5432,
    "expect_auth_ok": True,
}
"""

import socket

from .util import read_exact


def _build_pg_startup_packet(params):
    items = []
    for key, value in params.items():
        items.append(str(key).encode("utf-8") + b"\x00")
        items.append(str(value).encode("utf-8") + b"\x00")
    payload = b"".join(items) + b"\x00"
    length = 4 + 4 + len(payload)
    return length.to_bytes(4, "big") + (196608).to_bytes(4, "big") + payload


def _pg_read_message(sock, timeout):
    sock.settimeout(timeout)
    header = read_exact(sock, 5, timeout)
    if len(header) < 5:
        return None, b""
    tag = header[0:1]
    length = int.from_bytes(header[1:5], "big")
    payload = read_exact(sock, length - 4, timeout)
    return tag, payload


def check_postgres(cfg):
    host = cfg.get("host")
    port = int(cfg.get("port", 0))
    timeout = float(cfg.get("timeout", 5))
    user = cfg.get("user", "postgres")
    database = cfg.get("database", "postgres")
    expect_auth_ok = bool(cfg.get("expect_auth_ok", False))
    if not host or not port:
        return False, "postgres requires host and port"
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            startup = _build_pg_startup_packet({"user": user, "database": database})
            sock.sendall(startup)
            tag, payload = _pg_read_message(sock, timeout)
            if tag is None:
                return False, "postgres no response"
            if tag == b"E":
                return False, "postgres error response"
            if tag == b"R":
                auth_code = int.from_bytes(payload[:4], "big")
                if auth_code == 0:
                    return True, "postgres auth ok"
                if expect_auth_ok:
                    return False, f"postgres auth code {auth_code}"
                return True, f"postgres auth required ({auth_code})"
            return True, "postgres response ok"
    except OSError as exc:
        return False, f"postgres failed: {exc}"
