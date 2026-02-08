# MIT License
# Copyright (c) 2026 Franz Granlund
# See LICENSE file in the project root for full license information.

import json
import os
import shlex
import socket
import socketserver
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import main


def _get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _start_tcp_server(handler_cls):
    port = _get_free_port()
    server = socketserver.TCPServer(("127.0.0.1", port), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def _start_udp_server(handler_cls):
    port = _get_free_port()
    server = socketserver.UDPServer(("127.0.0.1", port), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def _start_http_server(handler_cls):
    port = _get_free_port()
    server = HTTPServer(("127.0.0.1", port), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


class BannerHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"SSH-2.0-test\r\n")


class EchoUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        sock = self.request[1]
        sock.sendto(data, self.client_address)


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        payload = {"status": "ok", "version": 1}
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Test", "yes")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


class MysqlHandshakeHandler(socketserver.BaseRequestHandler):
    def handle(self):
        payload = b"\x0a8.0.33\x00"
        length = len(payload)
        header = bytes([length & 0xFF, (length >> 8) & 0xFF, (length >> 16) & 0xFF, 0])
        self.request.sendall(header + payload)


def test_tcp_banner_expectation():
    server, port = _start_tcp_server(BannerHandler)
    try:
        ok, msg = main.check_tcp(
            {
                "host": "127.0.0.1",
                "port": port,
                "expect_contains": "SSH-",
                "read_bytes": 64,
            }
        )
        assert ok, msg
    finally:
        server.shutdown()
        server.server_close()


def test_udp_echo_expectation():
    server, port = _start_udp_server(EchoUDPHandler)
    try:
        ok, msg = main.check_udp(
            {
                "host": "127.0.0.1",
                "port": port,
                "message": "ping",
                "expect_response": True,
                "expect_contains": "ping",
            }
        )
        assert ok, msg
    finally:
        server.shutdown()
        server.server_close()


def test_http_json_expectation():
    server, port = _start_http_server(HealthHandler)
    try:
        ok, msg = main.check_http(
            {
                "url": f"http://127.0.0.1:{port}/health",
                "expect_status": 200,
                "expect_headers": {"X-Test": "yes"},
                "expect_json": {"status": "ok"},
            }
        )
        assert ok, msg
    finally:
        server.shutdown()
        server.server_close()


def test_mysql_handshake_expectation():
    server, port = _start_tcp_server(MysqlHandshakeHandler)
    try:
        ok, msg = main.check_mysql(
            {
                "host": "127.0.0.1",
                "port": port,
                "expect_server_version": "8.0",
            }
        )
        assert ok, msg
    finally:
        server.shutdown()
        server.server_close()


class PostgresHandshakeHandler(socketserver.BaseRequestHandler):
    def handle(self):
        header = self.request.recv(1024)
        if not header:
            return
        payload = (0).to_bytes(4, "big")
        length = 4 + len(payload)
        self.request.sendall(b"R" + length.to_bytes(4, "big") + payload)


class RabbitMQHandshakeHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"AMQP\x00\x00\x09\x01")


def test_postgres_handshake_expectation():
    server, port = _start_tcp_server(PostgresHandshakeHandler)
    try:
        ok, msg = main.check_postgres(
            {
                "host": "127.0.0.1",
                "port": port,
                "expect_auth_ok": True,
            }
        )
        assert ok, msg
    finally:
        server.shutdown()
        server.server_close()


def test_rabbitmq_handshake_expectation():
    server, port = _start_tcp_server(RabbitMQHandshakeHandler)
    try:
        ok, msg = main.check_rabbitmq(
            {
                "host": "127.0.0.1",
                "port": port,
                "expect_version": "0-9-1",
            }
        )
        assert ok, msg
    finally:
        server.shutdown()
        server.server_close()


def test_icmp_ping():
    ok, _msg = main.check_icmp({"host": "127.0.0.1", "count": 1, "timeout": 1})
    if not ok:
        pytest.skip("icmp ping blocked or unavailable")
    assert ok


def test_fail_command_runs_on_failure(tmp_path):
    marker = tmp_path / "failed.txt"
    cmd = shlex.join(
        [sys.executable, "-c", f"open(r'{marker}', 'w').write('x')"]
    )
    config = {
        "checks": [
            {
                "name": "missing-host",
                "type": "tcp",
                "fail_command": cmd,
            }
        ]
    }
    rc = main.run_checks(config)
    assert rc == 1
    assert marker.exists()


def test_global_command_runs_on_success(tmp_path):
    marker = tmp_path / "ok.txt"
    cmd = shlex.join(
        [sys.executable, "-c", f"open(r'{marker}', 'w').write('x')"]
    )
    ok_config = {
        "command": cmd,
        "checks": [],
    }
    rc = main.run_checks(ok_config)
    assert rc == 0
    assert marker.exists()


def test_global_fail_command_runs_on_failure(tmp_path):
    marker = tmp_path / "fail.txt"
    cmd = shlex.join(
        [sys.executable, "-c", f"open(r'{marker}', 'w').write('x')"]
    )
    config = {
        "fail_command": cmd,
        "checks": [
            {
                "name": "missing-host",
                "type": "tcp",
            }
        ],
    }
    rc = main.run_checks(config)
    assert rc == 1
    assert marker.exists()
