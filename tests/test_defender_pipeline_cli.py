"""Basic CLI/import tests for the ``defender_pipeline`` skeleton (P0.4).

These do not require Azure or Kubernetes access. They verify:

  * The package imports cleanly.
  * ``--help`` and ``--version`` work at every level.
  * All planned subcommands are registered.
  * Stub handlers exit with a clear message (EXIT_NOT_IMPLEMENTED = 2)
    so callers cannot mistake a stub for a successful run.
  * The frozen CSV contract constants match ``docs/contracts/``.

Later tasks (P0.5–P0.7) extend this file (or add sibling files) with
real behavior tests once the stubs get filled in.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


# ═══════════════════════════════════════════════════════════════════════════
# Package import
# ═══════════════════════════════════════════════════════════════════════════


class TestPackageImports:
    """Every module in the skeleton must import without side effects."""

    def test_top_level_import(self) -> None:
        import defender_pipeline
        assert hasattr(defender_pipeline, "__version__")

    def test_cli_import(self) -> None:
        from defender_pipeline import cli
        assert callable(cli.main)
        assert callable(cli.build_parser)

    def test_utils_csvio_import(self) -> None:
        from defender_pipeline.utils import csvio
        assert callable(csvio.csv_field)
        assert callable(csvio.csv_write_row)

    def test_contracts_modules_import(self) -> None:
        from defender_pipeline.findings import csv_contracts as fcc
        from defender_pipeline.openshift import csv_contracts as occ
        from defender_pipeline.reports import csv_contracts as rcc
        assert fcc.VULNERABLE_IMAGES_COLUMN_COUNT == 19
        assert occ.RESULTADO_CRUZAMENTO_COLUMN_COUNT == 24
        assert rcc.EXPANDED_COLUMN_COUNT == 22

    def test_openshift_coverage_import(self) -> None:
        from defender_pipeline.openshift.coverage import (
            EXIT_COMPLETE,
            EXIT_PARTIAL,
            Coverage,
            CoverageState,
        )
        assert EXIT_COMPLETE == 0
        assert EXIT_PARTIAL == 3
        assert len(list(CoverageState)) == 5
        assert Coverage.COMPLETE.value == "COMPLETE"


# ═══════════════════════════════════════════════════════════════════════════
# CLI dispatch
# ═══════════════════════════════════════════════════════════════════════════


def _run_module(*args: str) -> subprocess.CompletedProcess:
    """Invoke ``python -m defender_pipeline`` in a subprocess with the
    repo root on PYTHONPATH so the package resolves without install."""
    env_pypath = str(REPO_ROOT)
    return subprocess.run(
        [sys.executable, "-m", "defender_pipeline", *args],
        cwd=REPO_ROOT,
        env={"PYTHONPATH": env_pypath, "PATH": subprocess.os.environ.get("PATH", "")},
        capture_output=True,
        text=True,
        check=False,
    )


class TestCliHelp:
    """--help works at every level."""

    def test_top_level_help(self) -> None:
        r = _run_module("--help")
        assert r.returncode == 0
        assert "defender_pipeline" in r.stdout
        assert "scan" in r.stdout
        assert "cluster" in r.stdout
        assert "expand" in r.stdout
        assert "report" in r.stdout
        assert "all" in r.stdout
        assert "diff" in r.stdout

    def test_version(self) -> None:
        r = _run_module("--version")
        assert r.returncode == 0
        assert "defender_pipeline" in r.stdout

    @pytest.mark.parametrize("sub", ["scan", "cluster", "expand", "report", "all", "diff"])
    def test_subcommand_help(self, sub: str) -> None:
        r = _run_module(sub, "--help")
        assert r.returncode == 0, r.stderr
        assert sub in r.stdout


class TestSubcommandsStillStubbed:
    """Subcommands not yet implemented exit 2 with a task pointer.
    scan (P0.5), diff (P0.5), cluster (P0.6), expand (P0.7a) already
    implemented — their behavior lives in the sibling test files."""

    def test_report_stub_exits_2(self) -> None:
        r = _run_module("report")
        assert r.returncode == 2
        assert "P0.7" in r.stderr

    def test_all_stub_exits_2(self) -> None:
        r = _run_module("all", "--acr-name", "dummy")
        assert r.returncode == 2
        assert "P0.7" in r.stderr


class TestScanScopeMutualExclusion:
    """--repository / --repositories / --scan-image are mutually
    exclusive at the argparse level. This is a frozen behavior contract
    (see docs/contracts/cli-behavior.md)."""

    def test_repository_and_repositories_conflict(self) -> None:
        r = _run_module(
            "scan",
            "--acr-name", "x",
            "--repository", "a",
            "--repositories", "b,c",
        )
        # argparse mutually-exclusive returns exit code 2.
        assert r.returncode == 2
        assert "not allowed with" in r.stderr

    def test_repository_and_scan_image_conflict(self) -> None:
        r = _run_module(
            "scan",
            "--acr-name", "x",
            "--repository", "a",
            "--scan-image", "img:tag",
        )
        assert r.returncode == 2


# ═══════════════════════════════════════════════════════════════════════════
# csvio adapter — the byte-for-byte contract with bash csv_field
# ═══════════════════════════════════════════════════════════════════════════


class TestCsvIoBashCompat:
    """The csvio adapter is the diff-clean gate for CSV output. Any
    drift here breaks the migration validation."""

    def test_wraps_plain_value(self) -> None:
        from defender_pipeline.utils.csvio import csv_field
        assert csv_field("hello") == '"hello"'

    def test_internal_double_quote_becomes_apostrophe(self) -> None:
        from defender_pipeline.utils.csvio import csv_field
        assert csv_field('a "quoted" b') == "\"a 'quoted' b\""

    def test_newline_collapsed_to_space(self) -> None:
        from defender_pipeline.utils.csvio import csv_field
        assert csv_field("a\nb") == '"a b"'

    def test_none_becomes_empty_quoted(self) -> None:
        from defender_pipeline.utils.csvio import csv_field
        assert csv_field(None) == '""'

    def test_write_row_shape(self) -> None:
        import io

        from defender_pipeline.utils.csvio import csv_write_row
        buf = io.StringIO()
        csv_write_row(buf, ["a", 1, None])
        assert buf.getvalue() == '"a","1",""\n'


# ═══════════════════════════════════════════════════════════════════════════
# Coverage classifier
# ═══════════════════════════════════════════════════════════════════════════


class TestCoverageClassifier:
    """The 5-state → COMPLETE/PARTIAL aggregation is the exit-code gate
    documented in docs/contracts/resultado_cruzamento.md."""

    def test_all_ok_states_produce_complete(self) -> None:
        from defender_pipeline.openshift.coverage import (
            Coverage,
            CoverageState,
            summarize,
        )
        assert summarize([
            CoverageState.SUCCESS_WITH_PODS,
            CoverageState.NO_PODS,
            CoverageState.SUCCESS_WITH_PODS,
        ]) is Coverage.COMPLETE

    def test_any_err_state_produces_partial(self) -> None:
        from defender_pipeline.openshift.coverage import (
            Coverage,
            CoverageState,
            summarize,
        )
        for err in (CoverageState.RBAC_ERR, CoverageState.OC_ERR,
                    CoverageState.PARSE_ERR):
            assert summarize([
                CoverageState.SUCCESS_WITH_PODS, err,
            ]) is Coverage.PARTIAL, err

    def test_empty_state_list_is_complete(self) -> None:
        """No visited namespaces = nothing failed = COMPLETE. The
        cluster subcommand should decide separately whether to warn
        when zero namespaces were visible."""
        from defender_pipeline.openshift.coverage import Coverage, summarize
        assert summarize([]) is Coverage.COMPLETE

    def test_exit_code_mapping(self) -> None:
        from defender_pipeline.openshift.coverage import (
            Coverage,
            exit_code_for,
        )
        assert exit_code_for(Coverage.COMPLETE) == 0
        assert exit_code_for(Coverage.PARTIAL) == 3
