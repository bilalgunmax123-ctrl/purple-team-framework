![Detection CI](https://github.com/bilalgunmax123-ctrl/purple-team-framework/actions/workflows/detection_ci.yml/badge.svg)

# Purple Team Detection-as-Code Framework

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![CI](https://img.shields.io/badge/CI-GitHub%20Actions-blue)

> Sigma rules, synthetic telemetry generators, and an automated CI/CD testing pipeline for validating SOC detections.

This repository treats **detections like code**: every detection rule lives in version control, every rule is exercised against synthetic telemetry, and a CI pipeline proves the rules still parse and behave before they ship to the SIEM. No offensive tooling is included — the "emulators" here generate **synthetic test data only**; they perform no real malicious actions.

## Features

- **Detection Rules** — Sigma rules for common adversary techniques (DNS tunneling, process injection, LSASS access, scheduled-task persistence) in `rules/`.
- **Synthetic Telemetry Generation** — `emulators/emit_synthetic_sysmon.py` produces realistic Sysmon-style JSON test events (Event 1, 10, 22, 25) so detections can be exercised without running anything malicious.
- **Automated CI/CD Detection Testing** — `testing/matrix_harness.py` validates rule syntax, runs the detection matrix from `testing/detection_matrix_config.json`, optionally ingests synthetic events into Elasticsearch and polls for alerts, then prints a Matrix Report with exit codes:
  - `0` — all checks passed
  - `1` — detection gap (a rule did not fire as expected)
  - `2` — harness/config error

## MITRE ATT&CK Coverage

| Rule | Technique | Tactic | What it detects |
|---|---|---|---|
| `rules/dns_tunneling.yml` | T1071.004 | Command and Control | DNS tunneling via abnormally long / high-entropy DNS TXT queries |
| `rules/process_injection.yml` | T1055.002 | Defense Evasion | Portable Executable Injection via suspicious process-handle access masks |
| `rules/lsass_access.yml` | T1003.001 | Credential Access | LSASS memory access / process tampering for credential dumping |
| `rules/scheduled_task.yml` | T1053.005 | Persistence | Scheduled-task creation for persistence |

## Repository layout

```
purple-team-framework/
├── README.md
├── .gitignore
├── requirements.txt
├── rules/                      # Sigma detection rules (defensive)
│   ├── dns_tunneling.yml       # T1071.004
│   ├── process_injection.yml   # T1055
│   ├── lsass_access.yml        # T1003.001
│   └── scheduled_task.yml      # T1053.005
├── emulators/
│   └── emit_synthetic_sysmon.py  # synthetic test-data generator (no real actions)
├── testing/
│   ├── matrix_harness.py
│   └── detection_matrix_config.json
└── .github/workflows/detection_ci.yml
```

## Quick start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Generate synthetic test telemetry (writes JSON lines to stdout or a file)
python emulators/emit_synthetic_sysmon.py --count 50 --out events.jsonl

# 3. Run the detection matrix in offline check mode
python testing/matrix_harness.py --config testing/detection_matrix_config.json --check
```

To run the full pipeline against a live Elasticsearch instance, set `elasticsearch.enabled: true`
and the index/URL in `testing/detection_matrix_config.json`, then run without `--check`:

```bash
python testing/matrix_harness.py --config testing/detection_matrix_config.json
```

## Matrix Report Output

Example output of `testing/matrix_harness.py --check` (screenshot placeholder — replace with a real capture):

![Matrix Report](docs/matrix_report_preview.png)

## CI

Every push runs `.github/workflows/detection_ci.yml`: Python 3.10 setup, `pip install -r requirements.txt`,
a syntax check of the Python modules, and the harness in offline check mode.

## Disclaimer

Defensive security tooling for detection engineering and SOC validation. Use only in environments
you own or are authorized to test.
