import argparse
import json
import re
import shlex
import socket
import subprocess
import sys
import time
import urllib.request

import yaml


def _matches_expect(value, expect, expect_regex):
    if expect is None:
        return True
    if expect_regex:
        return re.search(str(expect), value) is not None
    return str(expect) in value


def _read_exact(sock, total, timeout):
    sock.settimeout(timeout)
    data = b""
    while len(data) < total:
        chunk = sock.recv(total - len(data))
        if not chunk:
            break
        data += chunk
    return data


def _read_available(sock, max_bytes, timeout):
    sock.settimeout(timeout)
    try:
        return sock.recv(max_bytes)
    except socket.timeout:
        return b""


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
                response = _read_available(sock, read_bytes, timeout)
            elapsed = time.time() - start
            if expect_contains is not None or expect_regex is not None:
                text = response.decode("utf-8", errors="replace")
                if not _matches_expect(text, expect_contains or expect_regex, bool(expect_regex)):
                    return False, "tcp response did not match expectation"
            return True, f"tcp connect ok in {elapsed:.3f}s"
    except OSError as exc:
        return False, f"tcp connect failed: {exc}"


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
                    if not _matches_expect(
                        text, expect_contains or expect_regex, bool(expect_regex)
                    ):
                        return False, "udp response did not match expectation"
            return True, "udp send ok"
    except OSError as exc:
        return False, f"udp failed: {exc}"


def _get_json_path(payload, path):
    current = payload
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def check_http(cfg):
    url = cfg.get("url")
    timeout = float(cfg.get("timeout", 5))
    method = cfg.get("method", "GET").upper()
    expect_status = cfg.get("expect_status", 200)
    headers = cfg.get("headers") or {}
    body = cfg.get("body")
    json_body = cfg.get("json")
    expect_body_contains = cfg.get("expect_body_contains")
    expect_body_regex = cfg.get("expect_body_regex")
    expect_headers = cfg.get("expect_headers") or {}
    expect_headers_regex = bool(cfg.get("expect_headers_regex", False))
    expect_json = cfg.get("expect_json") or {}
    if not url:
        return False, "http requires url"
    try:
        data = None
        req_headers = dict(headers)
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json")
        elif body is not None:
            data = str(body).encode("utf-8")
        req = urllib.request.Request(url, method=method, data=data, headers=req_headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.getcode()
            response_headers = {k.lower(): v for k, v in resp.headers.items()}
            response_body = resp.read().decode("utf-8", errors="replace")
        if isinstance(expect_status, list):
            ok = status in expect_status
        else:
            ok = status == int(expect_status)
        if ok:
            if expect_headers:
                for key, expected in expect_headers.items():
                    actual = response_headers.get(str(key).lower())
                    if actual is None:
                        return False, f"http missing header {key}"
                    if expect_headers_regex:
                        if re.search(str(expected), actual) is None:
                            return False, f"http header {key} mismatch"
                    elif str(actual) != str(expected):
                        return False, f"http header {key} mismatch"
            if expect_body_contains is not None:
                if str(expect_body_contains) not in response_body:
                    return False, "http body does not contain expectation"
            if expect_body_regex is not None:
                if re.search(str(expect_body_regex), response_body) is None:
                    return False, "http body regex did not match"
            if expect_json:
                try:
                    parsed = json.loads(response_body)
                except json.JSONDecodeError:
                    return False, "http body not valid json"
                for path, expected in expect_json.items():
                    actual = _get_json_path(parsed, path)
                    if actual != expected:
                        return False, f"http json {path} mismatch"
            return True, f"http {status} ok"
        return False, f"http status {status} != {expect_status}"
    except OSError as exc:
        return False, f"http failed: {exc}"


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
            header = _read_exact(sock, 4, timeout)
            if len(header) < 4:
                return False, "mysql handshake header incomplete"
            payload_len = header[0] | (header[1] << 8) | (header[2] << 16)
            payload = _read_exact(sock, payload_len, timeout)
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
                if not _matches_expect(
                    server_version,
                    expect_server_version,
                    expect_server_version_regex,
                ):
                    return False, "mysql server version mismatch"
            return True, f"mysql handshake ok: {server_version}"
    except OSError as exc:
        return False, f"mysql failed: {exc}"


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
    header = _read_exact(sock, 5, timeout)
    if len(header) < 5:
        return None, b""
    tag = header[0:1]
    length = int.from_bytes(header[1:5], "big")
    payload = _read_exact(sock, length - 4, timeout)
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
            header = _read_exact(sock, 8, timeout)
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


def run_command(command):
    if not command:
        return True
    try:
        args = shlex.split(command)
        result = subprocess.run(args, check=False)
        return result.returncode == 0
    except OSError:
        return False


def run_checks(config):
    checks = config.get("checks", [])
    if not isinstance(checks, list):
        print("config error: checks must be a list")
        return 1

    any_failed = False
    for item in checks:
        name = item.get("name", "(unnamed)")
        ctype = item.get("type")
        if ctype == "tcp":
            ok, msg = check_tcp(item)
        elif ctype == "udp":
            ok, msg = check_udp(item)
        elif ctype == "http":
            ok, msg = check_http(item)
        elif ctype == "mysql":
            ok, msg = check_mysql(item)
        elif ctype == "postgres":
            ok, msg = check_postgres(item)
        elif ctype == "rabbitmq":
            ok, msg = check_rabbitmq(item)
        else:
            ok, msg = False, f"unknown type: {ctype}"

        status = "ok" if ok else "fail"
        print(f"[{status}] {name}: {msg}")

        if ok:
            command = item.get("command")
            if command:
                cmd_ok = run_command(command)
                if not cmd_ok:
                    print(f"[fail] {name}: command failed")
                    any_failed = True
        else:
            fail_command = item.get("fail_command")
            if fail_command:
                cmd_ok = run_command(fail_command)
                if not cmd_ok:
                    print(f"[fail] {name}: fail command failed")
            any_failed = True

    if any_failed:
        fail_command = config.get("fail_command")
        if fail_command:
            cmd_ok = run_command(fail_command)
            if not cmd_ok:
                print("[fail] global fail_command failed")
        return 1

    command = config.get("command")
    if command:
        cmd_ok = run_command(command)
        if not cmd_ok:
            print("[fail] global command failed")
            return 1
    return 0


def main():
    parser = argparse.ArgumentParser(description="System connection checker")
    parser.add_argument(
        "-c",
        "--config",
        default="config.yaml",
        help="path to config YAML (default: config.yaml)",
    )
    args = parser.parse_args()

    try:
        with open(args.config, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
    except OSError as exc:
        print(f"failed to read config: {exc}")
        return 1
    except yaml.YAMLError as exc:
        print(f"invalid yaml: {exc}")
        return 1

    return run_checks(config)


if __name__ == "__main__":
    sys.exit(main())
