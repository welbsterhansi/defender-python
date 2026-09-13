"""Namespace coverage classification — frozen 5-state contract.

Mirrors ``check_ocp.sh``. Every namespace visited is classified into
exactly one of these states. The final coverage (COMPLETE / PARTIAL) is
derived from the aggregate — any ``*_ERR`` downgrades the run to
PARTIAL and forces exit code 3.

See ``docs/contracts/resultado_cruzamento.md`` and
``docs/contracts/cli-behavior.md``.
"""
from __future__ import annotations

from enum import Enum


class CoverageState(str, Enum):
    """Per-namespace classification."""

    SUCCESS_WITH_PODS = "SUCCESS_WITH_PODS"
    NO_PODS = "NO_PODS"
    RBAC_ERR = "RBAC_ERR"
    OC_ERR = "OC_ERR"
    PARSE_ERR = "PARSE_ERR"

    @property
    def is_ok(self) -> bool:
        """True when the state contributes to a COMPLETE run."""
        return self in (CoverageState.SUCCESS_WITH_PODS, CoverageState.NO_PODS)


class Coverage(str, Enum):
    """Overall run coverage — determines the process exit code."""

    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"


# Exit-code contract — frozen (mirrors check_ocp.sh).
EXIT_COMPLETE: int = 0
EXIT_PARTIAL: int = 3


def summarize(states: list[CoverageState]) -> Coverage:
    """Aggregate per-namespace states into a run-level coverage.

    A run is COMPLETE only when every visited namespace was classified
    into an ``is_ok`` state. Any ``*_ERR`` → PARTIAL.
    """
    if all(state.is_ok for state in states):
        return Coverage.COMPLETE
    return Coverage.PARTIAL


def exit_code_for(coverage: Coverage) -> int:
    """Map a run-level coverage to its process exit code (frozen)."""
    return EXIT_COMPLETE if coverage is Coverage.COMPLETE else EXIT_PARTIAL
