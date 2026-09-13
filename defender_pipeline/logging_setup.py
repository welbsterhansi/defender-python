"""Structured logging setup — matches ``defender.sh`` audit-trail lines.

Two modes (chosen at CLI parse time via ``--log-format``):

    text (default) — human-readable lines identical to the bash
        pipeline's format so existing dashboards / log parsers work
        unchanged.
    json           — structured JSON per line, opt-in for future
        aggregators (Splunk/ELK).

Both write to stderr and always emit a per-run ``run-<ts>-<pid>.log``
under ``./logs/`` (best-effort — a filesystem error never gates the
engine).

Implemented at the level needed by ``cli.py``; extended by later tasks
as new subcommands land.
"""
from __future__ import annotations

import logging
import os
import sys
from datetime import UTC, datetime
from pathlib import Path


def setup(*, log_format: str = "text", level: str = "INFO") -> logging.Logger:
    """Configure and return the root logger for ``defender_pipeline``.

    Idempotent: safe to call multiple times (subsequent calls short-
    circuit if handlers are already attached).
    """
    root = logging.getLogger("defender_pipeline")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    if root.handlers:
        return root

    handler = logging.StreamHandler(sys.stderr)
    if log_format == "json":
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(_TextFormatter())
    root.addHandler(handler)

    # Best-effort file handler (never fails the engine).
    try:
        logs_dir = Path("logs")
        logs_dir.mkdir(exist_ok=True)
        ts = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        fh = logging.FileHandler(logs_dir / f"run-{ts}-{os.getpid()}.log")
        fh.setFormatter(_TextFormatter())
        root.addHandler(fh)
    except OSError as exc:
        root.warning("logging: file handler disabled (%s)", exc)

    return root


class _TextFormatter(logging.Formatter):
    """Mirror the bash audit-trail shape: ``[UTC-timestamp] LEVEL  message``."""

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, tz=UTC).strftime(
            "%Y-%m-%dT%H:%M:%SZ",
        )
        return f"[{ts}] {record.levelname:<5} {record.getMessage()}"


class _JsonFormatter(logging.Formatter):
    """One JSON object per line — opt-in via ``--log-format json``."""

    def format(self, record: logging.LogRecord) -> str:
        import json
        payload = {
            "ts": datetime.fromtimestamp(
                record.created, tz=UTC,
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        return json.dumps(payload, ensure_ascii=False)
