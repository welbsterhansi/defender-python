# Pipeline contracts — frozen baseline

This directory documents the **frozen contracts** of the current
Bash + Python pipeline. These specs are the reference the future
Python API-first migration (tasks P0.3–P0.7) must preserve **byte-for-byte
or semantically equivalent** until the deprecation plan in task P0.8 is
explicitly approved.

## Why "frozen"

Downstream consumers (dashboards, other scripts, security officers'
spreadsheets, our own `report.py`) depend on the exact column names,
order, and semantics of these artifacts. Any drift — even a rename that
"looks harmless" — silently breaks something.

The Python migration is a **producer swap**, not a schema change.

## What is frozen

| Artifact | Producer | Rows | Cols | Spec |
|---|---|---|---|---|
| `vulnerable_images_report.csv` | `defender.sh` + `enrich_cvedetails.py` | one per (repo, digest, cveId) | **19** | [vulnerable_images_report.md](vulnerable_images_report.md) |
| `resultado_cruzamento.csv` | `check_ocp.sh` | one per (workload × image), CVEs aggregated | **24** | [resultado_cruzamento.md](resultado_cruzamento.md) |
| `expanded.csv` | `expandcsv.py` | one per (workload × image × cveId) | **22** | [expanded.md](expanded.md) |
| `vulnerability_report.html` | `report.py` | single-file HTML with 2 tabs (Images/Cluster) | — | [vulnerability_report_html.md](vulnerability_report_html.md) |

## What is also frozen (behavior, not schema)

- CLI flag semantics: [cli-behavior.md](cli-behavior.md).
- Coverage classification of `check_ocp.sh` (`SUCCESS_WITH_PODS`,
  `NO_PODS`, `RBAC_ERR`, `OC_ERR`, `PARSE_ERR`) and the rule that a
  partial-coverage report must NOT be distributed as authoritative.
- Retry/backoff semantics of `defender.sh` (`[2, 5]s` per ARG call,
  3 attempts before abort).

## Enforcement

`tests/test_contracts.py` (added by task P0.2) reads the current producer
sources and asserts that each header matches the canonical spec below.
This is the safety net for the Python migration — the new Python path
must satisfy the same test suite.

**Any change to the contracts requires:**
1. Explicit approval in the task backlog (never silent).
2. Update to the doc in this directory.
3. Update to `tests/test_contracts.py`.
4. Update to **every downstream consumer** in the same PR.
