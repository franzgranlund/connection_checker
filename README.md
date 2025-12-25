Connection Checker

A Linux/macOS connection checker. It loads connection tests from YAML and runs a per-check command on success.

Setup
- Create/activate the venv.
- Install dependencies from requirements.txt.

Run
- python main.py
- python main.py --config config.yaml

Ubuntu 24.04 setup
- sudo apt update
- sudo apt install -y python3 python3-venv python3-pip git
- git clone <repo-url> && cd system_check
- python3 -m venv .venv
- source .venv/bin/activate
- pip install -r requirements.txt
- edit config.yaml with your targets
- python main.py --config config.yaml

Scheduling (cron)
- crontab -e
- add a line like:
  - */5 * * * * /usr/bin/env -i HOME="$HOME" PATH="/usr/bin:/bin" /path/to/system_check/.venv/bin/python /path/to/system_check/main.py --config /path/to/system_check/config.yaml >> /var/log/system_check.log 2>&1

Scheduling (systemd timer)
- create /etc/systemd/system/system-check.service:
  - [Unit]
    Description=System connection checker
  - [Service]
    Type=oneshot
    WorkingDirectory=/path/to/system_check
    ExecStart=/path/to/system_check/.venv/bin/python /path/to/system_check/main.py --config /path/to/system_check/config.yaml
- create /etc/systemd/system/system-check.timer:
  - [Unit]
    Description=Run system checker every 5 minutes
  - [Timer]
    OnBootSec=1min
    OnUnitActiveSec=5min
    Persistent=true
  - [Install]
    WantedBy=timers.target
- sudo systemctl daemon-reload
- sudo systemctl enable --now system-check.timer
- check status with: systemctl status system-check.timer

Tests
- pip install -r requirements-dev.txt
- pytest

Config
- command: shell command to run when all checks succeed
- fail_command: shell command to run when one or more checks fail
- checks: list of connection checks
- Each check supports:
  - name: label for logging
  - type: tcp | udp | http | mysql | postgres | rabbitmq
  - command: shell command to run when the check succeeds
  - fail_command: shell command to run when the check fails

TCP
- host, port, timeout
- send: optional payload to send after connect
- read_bytes: bytes to read for matching (default 1024)
- expect_contains: substring to match in response
- expect_regex: regex to match in response

UDP
- host, port, timeout, message
- expect_response: if true, waits for a response
- read_bytes, expect_contains, expect_regex

HTTP
- url, method, timeout
- headers: request headers map
- body: request body string
- json: request body as json, sets Content-Type if missing
- expect_status: int or list of ints
- expect_headers: response headers map (exact match, case-insensitive keys)
- expect_headers_regex: if true, header values are regex-matched
- expect_body_contains: substring
- expect_body_regex: regex
- expect_json: map of dot-paths to expected values

MySQL
- host, port, timeout
- expect_protocol_version (default 10)
- expect_server_version: substring or regex (use expect_server_version_regex)
- expect_server_version_regex: if true, interpret expect_server_version as regex

Postgres
- host, port, timeout
- user (default postgres), database (default postgres)
- expect_auth_ok: if true, require AuthenticationOk (code 0)

RabbitMQ
- host, port, timeout
- expect_protocol (default AMQP)
- expect_version (default 0-9-1)

Exit code
- 0 when all checks and commands succeed
- 1 if any check or command fails
