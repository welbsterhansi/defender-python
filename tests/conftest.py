"""
Shared pytest fixtures.

Generates realistic CSV artifacts in tmp_path so tests never touch the
repository root and clean themselves up. Schemas mirror the real outputs
of defender.sh, check_ocp.sh (grouped) and expandcsv.py.

Schema constants and the CSV writer live in `tests/_data.py` so any test
module can import them directly without relying on pytest's dynamic
conftest loading (which confuses static analyzers).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from tests._data import CRUZAMENTO_HEADER, DEFENDER_HEADER, write_csv

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Backward-compat alias — older test files may still import `_write_csv`.
_write_csv = write_csv


# --- defender.sh output fixtures -------------------------------------------

@pytest.fixture
def defender_csv_normal(tmp_path: Path) -> Path:
    """Two images, three CVEs, mix of patchable and exploit flags."""
    rows = [
        ["myapp/backend", "sha256:aaa111", "v1.2", "9.8", "CVE-2024-0001", "Critical",
         "os", "python", "django", "4.1.0", "4.2.11", "true",
         "Upgrade django", "FixAvailable", "45", "false", "true", "false",
         "2025-01-15T10:00:00Z"],
        ["myapp/backend", "sha256:aaa111", "v1.2", "10.0", "CVE-2024-0002", "Critical",
         "os", "java", "pgjdbc", "42.5.0", "42.7.2", "true",
         "Upgrade pgjdbc", "FixAvailable", "120", "true", "true", "true",
         "2025-01-15T10:00:00Z"],
        ["shared/base", "sha256:bbb222", "latest", "9.1", "CVE-2024-0003", "Critical",
         "os", "c", "expat", "2.4.7", "", "false",
         "No fix available", "NoFix", "365", "false", "false", "false",
         "2024-12-01T09:00:00Z"],
    ]
    return _write_csv(tmp_path / "defender_normal.csv", DEFENDER_HEADER, rows)


@pytest.fixture
def defender_csv_multiarch(tmp_path: Path) -> Path:
    """Same repository, two per-platform digests — for prefix/repo+cve fallback."""
    rows = [
        ["multiarch/app", "sha256:1234567890abcdef1111", "v1", "9.5", "CVE-2024-9001",
         "Critical", "os", "go", "openssl", "1.1.1t", "1.1.1w", "true",
         "Upgrade openssl", "FixAvailable", "60", "false", "false", "false", ""],
        ["multiarch/app", "sha256:1234567890abcdef2222", "v1", "9.5", "CVE-2024-9001",
         "Critical", "os", "go", "openssl", "1.1.1t", "1.1.1w", "true",
         "Upgrade openssl", "FixAvailable", "60", "false", "false", "false", ""],
    ]
    return _write_csv(tmp_path / "defender_multiarch.csv", DEFENDER_HEADER, rows)


@pytest.fixture
def defender_csv_empty(tmp_path: Path) -> Path:
    """Header only."""
    return _write_csv(tmp_path / "defender_empty.csv", DEFENDER_HEADER, [])


@pytest.fixture
def defender_csv_missing_columns(tmp_path: Path) -> Path:
    """Missing required 'cveId' — expandcsv.py must raise ValueError."""
    header = ["repository", "digest", "cvssScore"]
    rows = [["myapp/backend", "sha256:aaa111", "9.0"]]
    return _write_csv(tmp_path / "defender_missing.csv", header, rows)


# --- check_ocp.sh grouped output fixtures ---------------------------------

@pytest.fixture
def cruzamento_csv_new(tmp_path: Path) -> Path:
    """Grouped output — 1 workload with 2 CVEs on backend, 1 CVE on shared/base."""
    rows = [
        ["ns-app", "Deployment", "backend", "myapp/backend", "sha256:aaa111", "v1.2",
         "2", "Critical", "10.0",
         "CVE-2024-0001, CVE-2024-0002",
         "CVE-2024-0001:Critical;CVE-2024-0002:Critical",
         "os", "python", "django", "4.1.0", "4.2.11", "true",
         "Upgrade", "FixAvailable", "45", "false", "true", "false",
         "2025-01-15T10:00:00Z"],
        ["ns-shared", "StatefulSet", "database", "shared/base", "sha256:bbb222", "latest",
         "1", "Critical", "9.1",
         "CVE-2024-0003",
         "CVE-2024-0003:Critical",
         "os", "c", "expat", "2.4.7", "", "false",
         "No fix", "NoFix", "365", "false", "false", "false",
         "2024-12-01T09:00:00Z"],
    ]
    return _write_csv(tmp_path / "cruzamento_new.csv", CRUZAMENTO_HEADER, rows)


@pytest.fixture
def cruzamento_csv_legacy(tmp_path: Path) -> Path:
    """Legacy lowercase header — expandcsv.py must still parse it."""
    legacy_header = [c.lower() for c in CRUZAMENTO_HEADER]
    rows = [
        ["ns-app", "Deployment", "backend", "myapp/backend", "sha256:aaa111", "v1.2",
         "1", "Critical", "9.8",
         "CVE-2024-0001",
         "CVE-2024-0001:Critical",
         "", "", "", "", "", "",
         "", "", "", "", "", "", ""],
    ]
    return _write_csv(tmp_path / "cruzamento_legacy.csv", legacy_header, rows)
