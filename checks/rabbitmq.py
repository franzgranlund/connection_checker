import socket

from .util import read_exact


def check_rabbitmq(cfg):
    host = cfg.get("host")
    port = int(cfg.get("port", 0))
    timeout = float(cfg.get("timeout", 5))
    expect_protocol = cfg.get("expect_protocol", "AMQP")
    expect_version = cfg.get("expect_version", "0-9-1")
    if not host or not port:
        return False, "rabbitmq requires host and port"
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            header = read_exact(sock, 8, timeout)
            if len(header) < 8:
                return False, "rabbitmq header incomplete"
            protocol = header[:4].decode("ascii", errors="replace")
            if protocol != "AMQP":
                return False, "rabbitmq not amqp"
            version = f"{header[5]}-{header[6]}-{header[7]}"
            if expect_protocol and protocol != str(expect_protocol):
                return False, "rabbitmq protocol mismatch"
            if expect_version and version != expect_version:
                return False, f"rabbitmq version {version} != {expect_version}"
            return True, f"rabbitmq amqp {version} ok"
    except OSError as exc:
        return False, f"rabbitmq failed: {exc}"
