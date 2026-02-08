# MIT License
# Copyright (c) 2026 Franz Granlund
# See LICENSE file in the project root for full license information.

"""UDP check.

Config keys:
- host (str, required)
- port (int, required)
- timeout (float, optional, seconds, default 5)
- message (str, optional, default "ping")
- expect_response (bool, optional, default False)
- read_bytes (int, optional, default 1024)
- expect_contains (str, optional, substring match)
- expect_regex (str, optional, regex match)

Example:
cfg = {
    "host": "127.0.0.1",
    "port": 9999,
    "message": "ping",
    "expect_response": True,
    "expect_contains": "ping",
}
"""

import socket

from .util import matches_expect


def check_udp(cfg):
    host = cfg.get("host")
    port = int(cfg.get("port", 0))
    timeout = float(cfg.get("timeout", 5))
    message = cfg.get("message", "ping")
    expect_response = bool(cfg.get("expect_response", False))
    expect_contains = cfg.get("expect_contains")
    expect_regex = cfg.get("expect_regex")
    read_bytes = int(cfg.get("read_bytes", 1024))
    if not host or not port:
        return False, "udp requires host and port"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(message.encode("utf-8"), (host, port))
            if expect_response or expect_contains is not None or expect_regex is not None:
                data, _addr = sock.recvfrom(read_bytes)
                if expect_contains is not None or expect_regex is not None:
                    text = data.decode("utf-8", errors="replace")
                    if not matches_expect(
                        text, expect_contains or expect_regex, bool(expect_regex)
                    ):
                        return False, "udp response did not match expectation"
            return True, "udp send ok"
    except OSError as exc:
        return False, f"udp failed: {exc}"
