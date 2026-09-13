"""
Shared test constants and helpers.

Extracted from conftest.py so any test module can import them via
`from tests._data import ...` without relying on pytest's dynamic
conftest loading, which confuses static analyzers like pyright.
"""
from __future__ import annotations

import csv
from pathlib import Path

DEFENDER_HEADER = [
    "repository", "digest", "tag", "cvssScore", "cveId", "severity",
    "packageCategory", "packageLanguage", "packageName",
    "currentVersion", "fixedVersion", "patchable", "remediation",
    "fixStatus", "cveAgeDays", "isInExploitKit",
    "hasPublishedExploit", "hasVerifiedExploit", "lastPushedToRegistryUTC",
]

CRUZAMENTO_HEADER = [
    "NAMESPACE", "PARENT_TYPE", "PARENT_NAME", "REPOSITORY", "DIGEST", "TAG",
    "CVE_COUNT", "CRITICALITY", "CVSS_SCORE", "CVE_LIST", "CVE_SEVERITY_MAP",
    "PACKAGE_CATEGORY", "PACKAGE_LANGUAGE", "PACKAGE_NAME",
    "CURRENT_VERSION", "FIXED_VERSION", "PATCHABLE",
    "REMEDIATION", "FIX_STATUS", "CVE_AGE_DAYS",
    "IS_IN_EXPLOIT_KIT", "HAS_PUBLISHED_EXPLOIT", "HAS_VERIFIED_EXPLOIT",
    "LAST_PUSHED_TO_REGISTRY_UTC",
]


def write_csv(path: Path, header: list[str], rows: list[list[str]]) -> Path:
    """Write rows as a QUOTE_ALL CSV; return the path for chaining."""
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(header)
        w.writerows(rows)
    return path
