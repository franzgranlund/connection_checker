"""ICMP ping check (via system ping).

Config keys:
- host (str, required)
- count (int, optional, default 1)
- timeout (float, optional, seconds, default 2)
- max_rtt_ms (float, optional, maximum avg round-trip time)

Example:
cfg = {
    "host": "8.8.8.8",
    "count": 2,
    "timeout": 2,
    "max_rtt_ms": 50,
}
"""

import re
import subprocess
import sys


def _build_ping_args(host, count, timeout):
    args = ["ping", "-c", str(count)]
    if sys.platform.startswith("darwin"):
        # macOS: -W is wait time in milliseconds per reply
        args += ["-W", str(int(timeout * 1000))]
    else:
        # Linux: -W is time to wait for a reply in seconds
        args += ["-W", str(int(timeout))]
    args.append(host)
    return args


def _parse_avg_rtt_ms(output):
    # Linux: rtt min/avg/max/mdev = 0.026/0.026/0.026/0.000 ms
    # macOS: round-trip min/avg/max/stddev = 0.123/0.123/0.123/0.000 ms
    match = re.search(r"=\s*([0-9.]+)/([0-9.]+)/([0-9.]+)/", output)
    if not match:
        return None
    try:
        return float(match.group(2))
    except ValueError:
        return None


def check_icmp(cfg):
    host = cfg.get("host")
    count = int(cfg.get("count", 1))
    timeout = float(cfg.get("timeout", 2))
    max_rtt_ms = cfg.get("max_rtt_ms")
    if max_rtt_ms is not None:
        max_rtt_ms = float(max_rtt_ms)

    if not host:
        return False, "icmp requires host"

    args = _build_ping_args(host, count, timeout)
    try:
        result = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        return False, f"icmp failed: {exc}"

    output = (result.stdout or "") + (result.stderr or "")
    if result.returncode != 0:
        return False, "icmp ping failed"

    avg_rtt_ms = _parse_avg_rtt_ms(output)
    if max_rtt_ms is not None and avg_rtt_ms is not None:
        if avg_rtt_ms > max_rtt_ms:
            return False, f"icmp avg rtt {avg_rtt_ms:.2f}ms > {max_rtt_ms:.2f}ms"

    if avg_rtt_ms is not None:
        return True, f"icmp ok avg rtt {avg_rtt_ms:.2f}ms"
    return True, "icmp ok"
