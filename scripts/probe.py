#!/usr/bin/env python3
"""Read-only Windows SSH probe; uses only Python's standard library and ssh."""

import argparse
import base64
import datetime
import json
from pathlib import Path
import re
import subprocess
import time


def classify(stderr):
    message = stderr.lower()
    for needles, category in (
        (("host key verification failed", "remote host identification has changed"), "host_key_unverified"),
        (("operation not permitted",), "local_permission_or_sandbox"),
        (("permission denied", "authentication failed"), "authentication_failed"),
        (("connection refused",), "connection_refused"),
        (("timed out", "timeout"), "timeout"),
        (("could not resolve hostname",), "name_resolution_failed"),
        (("no route to host", "network is unreachable"), "network_unreachable"),
    ):
        if any(needle in message for needle in needles):
            return category
    return "ssh_or_remote_command_failed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="Existing SSH alias or user@hostname")
    parser.add_argument("--relay", action="store_true", help="Also inspect a CodexRelay deployment")
    parser.add_argument("--root", help="Remote CodexRelay root containing app/ and data/")
    parser.add_argument("--task-name", help="Existing Windows scheduled task name")
    parser.add_argument("--port", type=int, help="Remote loopback HTTP health port")
    parser.add_argument("--timeout", type=int, default=30, help="Overall timeout in seconds (5 to 120)")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@-]*", args.host):
        parser.error("Use an SSH alias, hostname, or user@hostname; options and shell characters are not accepted")
    if not 5 <= args.timeout <= 120:
        parser.error("--timeout must be between 5 and 120")

    if args.relay and (not args.root or not args.task_name or args.port is None):
        parser.error("--relay requires --root, --task-name and --port")
    if not args.relay and any(value is not None for value in (args.root, args.task_name, args.port)):
        parser.error("--root, --task-name and --port require --relay")
    if args.port is not None and not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    def ps_literal(value):
        return "'" + (value or "").replace("'", "''") + "'"

    payload = "$CheckRelay = " + ("$true" if args.relay else "$false") + "\n"
    payload += "$RemoteRoot = " + ps_literal(args.root) + "\n"
    payload += "$TaskName = " + ps_literal(args.task_name) + "\n"
    payload += "$HealthPort = " + str(args.port or 0) + "\n"
    # This fixed script contains no here-strings; trim indentation to fit cmd.exe.
    source = Path(__file__).with_name("probe.ps1").read_text(encoding="utf-8")
    payload += "\n".join(line.lstrip() for line in source.splitlines()
                         if line.strip() and not line.lstrip().startswith("#"))
    encoded = base64.b64encode(payload.encode("utf-16le")).decode("ascii")
    remote_command = "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand " + encoded
    if len(remote_command) > 8000:
        parser.error("Probe exceeds the Windows command length limit; shorten the fixed payload")
    options = (
        "BatchMode=yes", "StrictHostKeyChecking=yes", "UpdateHostKeys=no",
        "AddKeysToAgent=no", "IdentitiesOnly=yes", "ConnectionAttempts=1",
        "ConnectTimeout=10", "ControlMaster=no", "ControlPath=none",
        "ClearAllForwardings=yes", "ForwardAgent=no", "ForwardX11=no",
        "ServerAliveInterval=5", "ServerAliveCountMax=2", "LogLevel=ERROR",
    )
    command = ["ssh", "-T"]
    for option in options:
        command.extend(["-o", option])
    command.extend([args.host, remote_command])
    result = {
        "target": args.host,
        "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "scope": "ssh_and_relay" if args.relay else "ssh",
    }
    started = time.monotonic()
    code = 1
    try:
        process = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                                 encoding="utf-8", errors="replace", timeout=args.timeout, check=False)
        result["ssh_exit_code"] = process.returncode
        try:
            remote = json.loads(process.stdout.lstrip("\ufeff").strip())
        except (ValueError, TypeError):
            remote = None
        if isinstance(remote, dict) and remote.get("marker") == "WINDOWS_SSH_PROBE_OK":
            result["ssh_ok"] = True
            result["remote"] = remote
            expected = 0 if not args.relay or remote.get("relay_ok") is True else 2
            if process.returncode == expected:
                code = expected
            else:
                result["error_category"] = "unexpected_remote_exit"
        else:
            result["ssh_ok"] = False if process.returncode == 255 else None
            result["error_category"] = classify(process.stderr)
            if process.returncode == 0:
                result["error_category"] = "unexpected_probe_output"
    except subprocess.TimeoutExpired:
        result.update(ssh_ok=None, error_category="timeout")
    except OSError as error:
        result.update(ssh_ok=None, error_category="local_execution_failed", error_type=type(error).__name__)
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    result["check_passed"] = code == 0
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
