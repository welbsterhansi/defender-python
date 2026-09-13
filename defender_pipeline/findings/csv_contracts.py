"""Frozen 19-column contract for ``vulnerable_images_report.csv``.

Single source of truth on the Python side. Read by
``tests/test_contracts.py`` and enforced against the bash producer
(``defender.sh``) so both paths always emit the same shape.

See ``docs/contracts/vulnerable_images_report.md``.
"""
from __future__ import annotations

VULNERABLE_IMAGES_HEADER_COLUMNS: list[str] = [
    "repository", "digest", "tag", "cvssScore", "cveId", "severity",
    "packageCategory", "packageLanguage", "packageName",
    "currentVersion", "fixedVersion", "patchable", "remediation",
    "fixStatus", "cveAgeDays", "isInExploitKit", "hasPublishedExploit",
    "hasVerifiedExploit", "lastPushedToRegistryUTC",
]

VULNERABLE_IMAGES_COLUMN_COUNT: int = 19

assert len(VULNERABLE_IMAGES_HEADER_COLUMNS) == VULNERABLE_IMAGES_COLUMN_COUNT
