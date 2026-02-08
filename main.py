import argparse
import shlex
import subprocess
import sys

import yaml

from checks.http import check_http
from checks.mysql import check_mysql
from checks.postgres import check_postgres
from checks.rabbitmq import check_rabbitmq
from checks.tcp import check_tcp
from checks.udp import check_udp



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
