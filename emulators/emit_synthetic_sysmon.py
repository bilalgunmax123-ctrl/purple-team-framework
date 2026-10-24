#!/usr/bin/env python3
"""Synthetic Sysmon-style telemetry generator for detection testing.

Generates FAKE Sysmon-like JSON events (EventID 1, 10, 22, 25) to files or
stdout so Sigma rules can be exercised WITHOUT performing any real malicious
action. Nothing here touches DNS, processes, LSASS, or the task scheduler.

Usage:
    python emit_synthetic_sysmon.py --count 50 --out events.jsonl
    python emit_synthetic_sysmon.py --scenario dns_tunneling --count 10
"""

import argparse
import base64
import json
import os
import random
import sys
from datetime import datetime, timezone

HOST = "TESTHOST"
USER = r"TESTDOMAIN\tester"


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def evt_dns_tunneling(i: int) -> dict:
    payload = base64.b64encode(os.urandom(48)).decode().rstrip("=")
    return {
        "EventID": 22,
        "UtcTime": _ts(),
        "Computer": HOST,
        "User": USER,
        "ProcessId": 4000 + i,
        "Image": r"C:\Windows\System32\svchost.exe",
        "QueryName": f"{payload}.tunnel.example.com",
        "QueryType": "TXT",
        "QueryStatus": 0,
        "_scenario": "dns_tunneling",
    }


def evt_process_injection(i: int) -> dict:
    return {
        "EventID": 10,
        "UtcTime": _ts(),
        "Computer": HOST,
        "User": USER,
        "SourceProcessId": 5000 + i,
        "SourceImage": r"C:\Users\tester\AppData\Local\Temp\dropper.exe",
        "TargetProcessId": 1234,
        "TargetImage": r"C:\Windows\System32\notepad.exe",
        "GrantedAccess": "0x1410",
        "CallTrace": "UNKNOWN",
        "_scenario": "process_injection",
    }


def evt_lsass_access(i: int) -> dict:
    return {
        "EventID": 10,
        "UtcTime": _ts(),
        "Computer": HOST,
        "User": USER,
        "SourceProcessId": 6000 + i,
        "SourceImage": r"C:\Users\tester\AppData\Local\Temp\dumper.exe",
        "TargetProcessId": 700,
        "TargetImage": r"C:\Windows\System32\lsass.exe",
        "GrantedAccess": "0x143a",
        "CallTrace": "UNKNOWN",
        "_scenario": "lsass_access",
    }


def evt_scheduled_task(i: int) -> dict:
    return {
        "EventID": 1,
        "UtcTime": _ts(),
        "Computer": HOST,
        "User": USER,
        "ProcessId": 8000 + i,
        "Image": r"C:\Windows\System32\schtasks.exe",
        "CommandLine": 'schtasks /create /tn "Updater" /tr "C:\\Temp\\updater.exe" /sc daily',
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "_scenario": "scheduled_task",
    }


SCENARIOS = {
    "dns_tunneling": evt_dns_tunneling,
    "process_injection": evt_process_injection,
    "lsass_access": evt_lsass_access,
    "scheduled_task": evt_scheduled_task,
}


def main() -> int:
    ap = argparse.ArgumentParser(description="Emit synthetic Sysmon-style test events.")
    ap.add_argument("--count", type=int, default=20, help="events to generate")
    ap.add_argument("--scenario", choices=list(SCENARIOS) + ["mixed"], default="mixed")
    ap.add_argument("--out", default="-", help="output file ('-' for stdout)")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    random.seed(args.seed)
    names = list(SCENARIOS) if args.scenario == "mixed" else [args.scenario]

    out = sys.stdout if args.out == "-" else open(args.out, "w", encoding="utf-8")
    try:
        for i in range(args.count):
            name = random.choice(names)
            out.write(json.dumps(SCENARIOS[name](i)) + "\n")
    finally:
        if out is not sys.stdout:
            out.close()
    print(f"[emulator] wrote {args.count} synthetic events (scenario={args.scenario})",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
