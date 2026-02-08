import argparse
import logging
import shlex
import subprocess
import sys

import yaml

from checks.http import check_http
from checks.icmp import check_icmp
from checks.mysql import check_mysql
from checks.postgres import check_postgres
from checks.rabbitmq import check_rabbitmq
from checks.tcp import check_tcp
from checks.udp import check_udp


LOGGER = logging.getLogger("system_check")


def setup_logging(level_name):
    level = logging.INFO
    if level_name:
        level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
    )


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
        LOGGER.error("config error: checks must be a list")
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
        elif ctype == "icmp":
            ok, msg = check_icmp(item)
        elif ctype == "mysql":
            ok, msg = check_mysql(item)
        elif ctype == "postgres":
            ok, msg = check_postgres(item)
        elif ctype == "rabbitmq":
            ok, msg = check_rabbitmq(item)
        else:
            ok, msg = False, f"unknown type: {ctype}"

        if ok:
            LOGGER.info("[ok] %s: %s", name, msg)
        else:
            LOGGER.warning("[fail] %s: %s", name, msg)

        if ok:
            command = item.get("command")
            if command:
                cmd_ok = run_command(command)
                if not cmd_ok:
                    LOGGER.error("[fail] %s: command failed", name)
                    any_failed = True
        else:
            fail_command = item.get("fail_command")
            if fail_command:
                cmd_ok = run_command(fail_command)
                if not cmd_ok:
                    LOGGER.error("[fail] %s: fail command failed", name)
            any_failed = True

    if any_failed:
        fail_command = config.get("fail_command")
        if fail_command:
            cmd_ok = run_command(fail_command)
            if not cmd_ok:
                LOGGER.error("[fail] global fail_command failed")
        return 1

    command = config.get("command")
    if command:
        cmd_ok = run_command(command)
        if not cmd_ok:
            LOGGER.error("[fail] global command failed")
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
    parser.add_argument(
        "--log-level",
        default="INFO",
        help="logging level (default: INFO)",
    )
    args = parser.parse_args()
    setup_logging(args.log_level)

    try:
        with open(args.config, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
    except OSError as exc:
        LOGGER.error("failed to read config: %s", exc)
        return 1
    except yaml.YAMLError as exc:
        LOGGER.error("invalid yaml: %s", exc)
        return 1

    return run_checks(config)


if __name__ == "__main__":
    sys.exit(main())
