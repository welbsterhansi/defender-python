"""Retry decorators backed by ``tenacity``.

Two policies exposed:

  * ``arg_call_retry`` — 3 attempts, exponential backoff [1s, 2s, 5s]
    on transient errors (5xx, 429, timeouts, connection failures).
    Does NOT retry on ``BatchTooComplex`` — that needs split, not retry.
    Does NOT retry on ``ClientAuthenticationError`` — auth is broken.
  * ``acr_call_retry`` — same, plus does NOT retry on 403 (RBAC — the
    ACR is not accessible; retrying won't help).

Import is guarded so callers who don't touch retry paths don't fail on
missing extras.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

try:
    from tenacity import (
        retry,
        retry_if_exception,
        stop_after_attempt,
        wait_exponential,
    )
    _TENACITY_AVAILABLE = True
except ImportError:  # pragma: no cover — extras not installed
    _TENACITY_AVAILABLE = False

from defender_pipeline.utils.batching import (
    BatchExhausted,
    BatchTooComplex,
)


class TransientARGError(Exception):
    """Wraps a 5xx / 429 / network error from Azure Resource Graph so
    the retry decorator can recognize it. Non-transient errors (auth,
    complexity, bad KQL) propagate unchanged."""


def _is_retryable(exc: BaseException) -> bool:
    """Retry policy: transient errors only.

    ``BatchTooComplex`` needs to be split by the caller, not retried
    identically. ``BatchExhausted`` is terminal by definition.
    Authentication / permission errors are terminal.
    """
    if isinstance(exc, BatchTooComplex | BatchExhausted):
        return False
    if isinstance(exc, TransientARGError):
        return True
    # Azure SDK raises HttpResponseError with .status_code — treat 5xx / 429
    # as transient; anything else terminal.
    status = getattr(exc, "status_code", None)
    if status is not None:
        return status in {429, 500, 502, 503, 504, 408}
    # Network-level failures (ConnectionError, TimeoutError).
    return isinstance(exc, ConnectionError | TimeoutError)


def arg_call_retry(func: Callable[..., Any]) -> Callable[..., Any]:
    """3-attempts, exponential backoff for a single Azure Resource Graph
    call. See module docstring for the retry policy."""
    if not _TENACITY_AVAILABLE:
        raise ImportError(
            "tenacity is required for retry policies — install extras: "
            "pip install -e .[pipeline]",
        )
    return retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception(_is_retryable),
        reraise=True,
    )(func)
