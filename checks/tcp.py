"""TCP check.

Config keys:
- host (str, required)
- port (int, required)
- timeout (float, optional, seconds, default 5)
- send (str, optional, payload sent after connect)
- read_bytes (int, optional, default 1024)
- expect_contains (str, optional, substring match)
- expect_regex (str, optional, regex match)

Example:
cfg = {
    "host": "127.0.0.1",
    "port": 22,
    "timeout": 2,
    "send": "hello",
    "read_bytes": 64,
    "expect_contains": "SSH-",
}
"""

import socket
import time

from .util import matches_expect, read_available


def check_tcp(cfg):
    host = cfg.get("host")
    port = int(cfg.get("port", 0))
    timeout = float(cfg.get("timeout", 5))
    send_data = cfg.get("send")
    read_bytes = int(cfg.get("read_bytes", 1024))
    expect_contains = cfg.get("expect_contains")
    expect_regex = cfg.get("expect_regex")
    if not host or not port:
        return False, "tcp requires host and port"
    start = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            if send_data is not None:
                sock.sendall(str(send_data).encode("utf-8"))
            response = b""
            if expect_contains is not None or expect_regex is not None:
                response = read_available(sock, read_bytes, timeout)
            elapsed = time.time() - start
            if expect_contains is not None or expect_regex is not None:
                text = response.decode("utf-8", errors="replace")
                if not matches_expect(
                    text, expect_contains or expect_regex, bool(expect_regex)
                ):
                    return False, "tcp response did not match expectation"
            return True, f"tcp connect ok in {elapsed:.3f}s"
    except OSError as exc:
        return False, f"tcp connect failed: {exc}"
