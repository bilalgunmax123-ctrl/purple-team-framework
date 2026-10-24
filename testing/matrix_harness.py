#!/usr/bin/env python3
"""Detection matrix harness.

Validates Sigma rules and (optionally) proves they fire by ingesting
synthetic events into Elasticsearch and polling for alerts.

Exit codes:
    0 - all checks passed
    1 - detection gap (a rule did not fire as expected)
    2 - harness or configuration error

Offline check mode (no Elasticsearch needed, used by CI):
    python matrix_harness.py --config detection_matrix_config.json --check
"""

import argparse
import json
import sys
import time
from pathlib import Path

import yaml

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

EXIT_OK = 0
EXIT_GAP = 1
EXIT_ERROR = 2

REQUIRED_RULE_FIELDS = {"title", "id", "description", "detection", "level"}


def load_config(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[harness] ERROR: cannot read config {path}: {exc}", file=sys.stderr)
        raise SystemExit(EXIT_ERROR)


def validate_rule(rule_path: Path) -> list:
    """Return a list of validation problems (empty = valid)."""
    problems = []
    try:
        rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [f"YAML parse error: {exc}"]
    if not isinstance(rule, dict):
        return ["rule is not a mapping"]
    missing = REQUIRED_RULE_FIELDS - set(rule)
    if missing:
        problems.append(f"missing fields: {sorted(missing)}")
    det = rule.get("detection")
    if not isinstance(det, dict) or "condition" not in det:
        problems.append("detection block must contain a 'condition'")
    return problems


def es_ingest(es: dict, index: str, events: list) -> bool:
    if requests is None:
        print("[harness] ERROR: 'requests' not installed", file=sys.stderr)
        return False
    url = f"{es['url'].rstrip('/')}/{index}/_bulk"
    body = "".join(
        '{"index":{}}\n' + json.dumps(e) + "\n" for e in events
    )
    try:
        r = requests.post(url, data=body,
                          headers={"Content-Type": "application/x-ndjson"},
                          timeout=30)
        r.raise_for_status()
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"[harness] ERROR: bulk ingest failed: {exc}", file=sys.stderr)
        return False


def es_poll_alert(es: dict, index: str, rule_id: str, timeout_s: int) -> bool:
    """Poll Elasticsearch until an alert referencing rule_id appears."""
    if requests is None:
        return False
    url = f"{es['url'].rstrip('/')}/{index}/_search"
    query = {"query": {"match": {"rule_id": rule_id}}, "size": 1}
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            r = requests.post(url, json=query, timeout=15)
            r.raise_for_status()
            hits = r.json().get("hits", {}).get("total", {})
            total = hits.get("value", 0) if isinstance(hits, dict) else hits
            if total and int(total) > 0:
                return True
        except Exception as exc:  # noqa: BLE001
            print(f"[harness] WARN: poll error: {exc}", file=sys.stderr)
        time.sleep(es.get("poll_interval_s", 5))
    return False


def run_check_mode(cfg: dict, base: Path) -> int:
    """Offline validation: rule syntax + config sanity. No ES required."""
    rows, failed = [], False
    for entry in cfg.get("rules", []):
        rule_file = base / entry["file"]
        problems = validate_rule(rule_file)
        status = "PASS" if not problems else "FAIL"
        if problems:
            failed = True
        rows.append((entry["id"], entry["file"], status,
                     "; ".join(problems) if problems else "syntax OK"))
    print_matrix(rows)
    return EXIT_GAP if failed else EXIT_OK


def run_full_mode(cfg: dict, base: Path) -> int:
    es = cfg.get("elasticsearch", {})
    if not es.get("enabled"):
        print("[harness] ERROR: elasticsearch.enabled is false; "
              "use --check for offline mode", file=sys.stderr)
        return EXIT_ERROR
    try:
        from emulators.emit_synthetic_sysmon import (  # noqa: E402
            SCENARIOS, _ts)
    except ImportError:
        sys.path.insert(0, str(base.parent))
        from emulators.emit_synthetic_sysmon import SCENARIOS  # noqa: E402

    rows, gap = [], False
    for entry in cfg.get("rules", []):
        rid, scenario = entry["id"], entry["scenario"]
        rule_file = base / entry["file"]
        problems = validate_rule(rule_file)
        if problems:
            rows.append((rid, entry["file"], "FAIL", "; ".join(problems)))
            gap = True
            continue
        events = [SCENARIOS[scenario](i) for i in range(es.get("events_per_rule", 5))]
        if not es_ingest(es, es["index"], events):
            return EXIT_ERROR
        fired = es_poll_alert(es, es.get("alert_index", "alerts"),
                              rid, es.get("poll_timeout_s", 60))
        rows.append((rid, entry["file"], "PASS" if fired else "GAP",
                     "alert observed" if fired else "no alert within timeout"))
        gap = gap or not fired
    print_matrix(rows)
    return EXIT_GAP if gap else EXIT_OK


def print_matrix(rows: list) -> None:
    print("\n==== Detection Matrix Report ====")
    print(f"{'RULE ID':<40} {'FILE':<28} {'STATUS':<6} DETAIL")
    print("-" * 110)
    for rid, fname, status, detail in rows:
        print(f"{rid:<40} {fname:<28} {status:<6} {detail}")
    print("=" * 110 + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description="Detection matrix harness")
    ap.add_argument("--config", required=True, help="path to detection_matrix_config.json")
    ap.add_argument("--check", action="store_true",
                    help="offline mode: validate rules/config only")
    args = ap.parse_args()

    cfg_path = Path(args.config)
    cfg = load_config(cfg_path)
    base = cfg_path.parent

    if args.check:
        return run_check_mode(cfg, base)
    return run_full_mode(cfg, base)


if __name__ == "__main__":
    raise SystemExit(main())
