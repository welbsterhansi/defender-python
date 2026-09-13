"""Batch-split-on-failure orchestrator.

The Azure Resource Graph engine sometimes rejects a large query with
``UnexpectedQueryExecutionError`` — meaning "too complex", not "try
again". Retrying the same call does not help; we must **split the batch
in half** and try the halves independently.

Ports the semantics of ``_scan_batch_recursive`` in ``defender.sh``.
"""
from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from typing import Any, TypeVar

log = logging.getLogger("defender_pipeline")


T = TypeVar("T")


class BatchTooComplex(Exception):
    """Raised by a batch-runner when ARG returns ``UnexpectedQueryExecutionError``.
    The caller should split the batch in half and retry."""


class BatchExhausted(Exception):
    """Raised when a single-item batch still fails. Terminal — indicates
    a structural problem, not a size problem."""


def run_batched_with_split(
    items: Sequence[T],
    run_batch: Callable[[Sequence[T]], list[Any]],
    *,
    initial_batch_size: int,
    on_batch_start: Callable[[int, int, int], None] | None = None,
) -> list[Any]:
    """Run ``run_batch(chunk)`` in ``initial_batch_size`` chunks.

    On :class:`BatchTooComplex`, splits the failing chunk in half and
    recurses on both halves. Never falls silently to 1-by-1 — every
    split logs a WARN so operators know when the size is too big.

    A single-item chunk that fails raises :class:`BatchExhausted`.

    Args:
        items: full input list.
        run_batch: callable that processes one chunk.
        initial_batch_size: preferred chunk size (may be split on failure).
        on_batch_start: optional callback ``(start, end, total)``, invoked
            before each initial-size chunk is dispatched (not per split).
            Used for per-batch visual progress in the CLI.
    """
    results: list[Any] = []
    start = 0
    while start < len(items):
        end = min(start + initial_batch_size, len(items))
        chunk = items[start:end]
        if on_batch_start is not None:
            on_batch_start(start, end, len(items))
        results.extend(_run_chunk_recursive(chunk, run_batch))
        start = end
    return results


def _run_chunk_recursive(
    chunk: Sequence[T],
    run_batch: Callable[[Sequence[T]], list[Any]],
) -> list[Any]:
    """Try to run ``chunk`` in one call. On :class:`BatchTooComplex`,
    split in half and recurse."""
    try:
        return run_batch(chunk)
    except BatchTooComplex:
        if len(chunk) <= 1:
            item_repr = repr(chunk[0]) if chunk else "<empty>"
            raise BatchExhausted(
                f"single-item batch failed structurally: {item_repr}",
            ) from None
        half = len(chunk) // 2
        left, right = chunk[:half], chunk[half:]
        log.warning(
            "batch of %d items too complex; splitting to %d + %d",
            len(chunk), len(left), len(right),
        )
        return _run_chunk_recursive(left, run_batch) \
            + _run_chunk_recursive(right, run_batch)
