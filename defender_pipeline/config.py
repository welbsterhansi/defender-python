"""Global configuration knobs — parallelism, batch sizes, timeouts.

Values are the sensible defaults from ``docs/python-architecture.md``.
Each is overrideable via CLI flags (see ``cli.py``) or env vars.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Config:
    """Pipeline-wide settings."""

    # Concurrency (see docs/python-architecture.md §5).
    max_workers: int = 8

    # Batch sizes for the two-phase batched scan
    # (mirrors defender.sh — see docs/mdvm-two-phase-benchmark.md).
    assessments_batch_size: int = 50
    cvedetails_batch_size: int = 500

    # Retry / timeout defaults for Azure SDK calls.
    request_timeout_s: int = 60
    retry_total: int = 3

    # ARG endpoint — the P2-validated api-version.
    arg_api_version: str = "2022-10-01"


def from_env() -> Config:
    """Build a :class:`Config` overriding defaults from env vars."""
    return Config(
        max_workers=int(os.environ.get("DEFENDER_PIPELINE_PARALLELISM", "8")),
        assessments_batch_size=int(
            os.environ.get("DEFENDER_PIPELINE_ASSESSMENTS_BATCH", "50"),
        ),
        cvedetails_batch_size=int(
            os.environ.get("DEFENDER_PIPELINE_CVEDETAILS_BATCH", "500"),
        ),
        request_timeout_s=int(
            os.environ.get("DEFENDER_PIPELINE_TIMEOUT_S", "60"),
        ),
        retry_total=int(os.environ.get("DEFENDER_PIPELINE_RETRIES", "3")),
    )
