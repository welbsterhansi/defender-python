"""Tests for ``defender_pipeline.reports.expand``.

Covers:
  * 3-level lookup ladder (full → repo+cve → digest-prefix).
  * Legacy lowercase schema for ``resultado_cruzamento.csv``.
  * Missing files, missing columns, and empty inputs.
  * CLI wiring: ``python -m defender_pipeline expand ...``.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from defender_pipeline.reports.csv_contracts import EXPANDED_HEADER_COLUMNS
from defender_pipeline.reports.expand import (
    ExpandOptions,
    _lookup,
    expand_cves,
    load_vulnerability_data,
    run_expand,
    split_cves,
)
from tests._data import CRUZAMENTO_HEADER, DEFENDER_HEADER, write_csv

# ---------------------------------------------------------------------------
# Header contract
# ---------------------------------------------------------------------------


class TestHeaderContract:
    def test_output_header_matches_frozen_contract(
        self,
        defender_csv_normal: Path,
        cruzamento_csv_new: Path,
        tmp_path: Path,
    ) -> None:
        out = tmp_path / "expanded.csv"
        run_expand(ExpandOptions(
            cruzamento=cruzamento_csv_new,
            vulnerabilities=defender_csv_normal,
            output=out,
        ))
        header = out.read_text(encoding="utf-8").splitlines()[0]
        # QUOTE_ALL wraps every column
        expected = ",".join(f'"{c}"' for c in EXPANDED_HEADER_COLUMNS)
        assert header == expected


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


class TestErrorPaths:
    def test_missing_cruzamento_file(
        self, defender_csv_normal: Path, tmp_path: Path
    ) -> None:
        with pytest.raises(FileNotFoundError, match="cruzamento CSV not found"):
            run_expand(ExpandOptions(
                cruzamento=tmp_path / "does_not_exist.csv",
                vulnerabilities=defender_csv_normal,
                output=tmp_path / "out.csv",
            ))

    def test_missing_vulnerabilities_file(
        self, cruzamento_csv_new: Path, tmp_path: Path
    ) -> None:
        with pytest.raises(FileNotFoundError, match="vulnerabilities CSV not found"):
            run_expand(ExpandOptions(
                cruzamento=cruzamento_csv_new,
                vulnerabilities=tmp_path / "nope.csv",
                output=tmp_path / "out.csv",
            ))

    def test_defender_missing_required_columns(
        self, cruzamento_csv_new: Path, defender_csv_missing_columns: Path,
        tmp_path: Path,
    ) -> None:
        with pytest.raises(ValueError, match="missing required defender.sh columns"):
            run_expand(ExpandOptions(
                cruzamento=cruzamento_csv_new,
                vulnerabilities=defender_csv_missing_columns,
                output=tmp_path / "out.csv",
            ))


# ---------------------------------------------------------------------------
# Lookup ladder — mirrors expandcsv unit tests to guard against drift
# ---------------------------------------------------------------------------


class TestLookupLadder:
    def _idx(self, entries):
        idx_full, idx_digest, idx_prefix = {}, {}, {}
        for repo, digest, cve, detail in entries:
            idx_full[(repo, digest, cve)] = detail
            idx_digest.setdefault((repo, cve), detail)
            prefix = digest.replace("sha256:", "")[:16]
            idx_prefix.setdefault((repo, prefix, cve), detail)
        return idx_full, idx_digest, idx_prefix

    def test_level_1_exact(self) -> None:
        want = {"CVSS_SCORE": "9.8"}
        idxs = self._idx([("r", "sha256:aaa", "CVE-1", want)])
        assert _lookup(*idxs, "r", "sha256:aaa", "CVE-1") == want

    def test_level_2_repo_plus_cve(self) -> None:
        want = {"CVSS_SCORE": "9.8"}
        idxs = self._idx([("r", "sha256:child", "CVE-1", want)])
        assert _lookup(*idxs, "r", "sha256:manifest", "CVE-1") == want

    def test_level_3_digest_prefix(self) -> None:
        want = {"CVSS_SCORE": "9.0"}
        full = "sha256:abcdef1234567890" + "f" * 48
        variant = "sha256:abcdef1234567890" + "x" * 48
        idxs = self._idx([("r", full, "CVE-1", want)])
        idxs[1].clear()  # force prefix path
        assert _lookup(*idxs, "r", variant, "CVE-1") == want

    def test_all_miss_returns_empty(self) -> None:
        idxs = self._idx([("r", "sha256:aaa", "CVE-1", {"x": "y"})])
        assert _lookup(*idxs, "other", "sha256:zzz", "CVE-9") == {}


class TestSplitAndLoad:
    def test_split_cves_dedup_and_strip(self) -> None:
        assert split_cves(" CVE-A , CVE-B, CVE-A ,, CVE-C") == [
            "CVE-A", "CVE-B", "CVE-C",
        ]

    def test_split_cves_none(self) -> None:
        assert split_cves(None) == []

    def test_load_skips_rows_missing_key_fields(self, tmp_path: Path) -> None:
        rows = [
            ["good/repo", "sha256:aaa", "v1", "9.0", "CVE-1", "Critical",
             "", "", "", "", "", "", "", "", "", "", "", "", ""],
            ["", "sha256:bbb", "v1", "9.0", "CVE-2", "Critical",
             "", "", "", "", "", "", "", "", "", "", "", "", ""],
            ["good/repo", "", "v1", "9.0", "CVE-3", "Critical",
             "", "", "", "", "", "", "", "", "", "", "", "", ""],
        ]
        path = write_csv(tmp_path / "partial.csv", DEFENDER_HEADER, rows)
        idx_full, _, _ = load_vulnerability_data(path)
        assert list(idx_full) == [("good/repo", "sha256:aaa", "CVE-1")]

    def test_expand_dedupes_within_workload(
        self, defender_csv_normal: Path, tmp_path: Path
    ) -> None:
        rows = [[
            "prd", "Deployment", "app", "myapp/backend",
            "sha256:aaa111", "v1.2",
            "1", "Critical", "9.8",
            "CVE-2024-0001, CVE-2024-0001",
            "CVE-2024-0001:Critical",
            "", "", "", "", "", "", "", "", "", "", "", "", "",
        ]]
        cruz = write_csv(tmp_path / "cruz.csv", CRUZAMENTO_HEADER, rows)
        idxs = load_vulnerability_data(defender_csv_normal)
        assert len(expand_cves(cruz, *idxs)) == 1


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------


class TestCLI:
    def test_expand_subcommand_runs_end_to_end(
        self,
        defender_csv_normal: Path,
        cruzamento_csv_new: Path,
        tmp_path: Path,
    ) -> None:
        out = tmp_path / "expanded.csv"
        result = subprocess.run(
            [
                sys.executable, "-m", "defender_pipeline", "expand",
                "--cruzamento", str(cruzamento_csv_new),
                "--vulnerabilities", str(defender_csv_normal),
                "--output", str(out),
            ],
            capture_output=True, text=True, check=False,
        )
        assert result.returncode == 0, result.stderr
        assert out.exists()
        assert "expand complete" in result.stderr
        # Header + 3 data rows (from cruzamento_csv_new fixture).
        assert len(out.read_text().splitlines()) == 4
