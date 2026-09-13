"""Bounded-parallelism helpers on top of ``concurrent.futures``.

The pipeline uses threads (not asyncio) — see
``docs/python-architecture.md`` §5 for the rationale.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import TypeVar

T = TypeVar("T")
R = TypeVar("R")


def parallel_map(
    fn: Callable[[T], R],
    items: Iterable[T],
    *,
    max_workers: int = 8,
) -> Iterator[R]:
    """Map ``fn`` over ``items`` using up to ``max_workers`` threads.

    Order-preserving. Propagates the first exception. Not lazy — collects
    all items into a list to submit them; use plain iteration for very
    large datasets.
    """
    items_list = list(items)
    if not items_list:
        return iter([])
    if max_workers <= 1:
        return (fn(item) for item in items_list)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        results = list(pool.map(fn, items_list))
    return iter(results)
