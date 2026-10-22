"""Azure Resource Graph client wrapper.

Uses ``azure-mgmt-resourcegraph`` with api-version 2022-10-01 — the
version proven to correctly resolve JOINs against
``microsoft.security/cvedetails`` (older versions returned enriched=0
rows; see erros.md).

Design notes:

  * ``run_query`` handles one call (with skip-token if supplied).
    Applies :func:`arg_call_retry` for transient failures (5xx / 429).
  * ``iter_pages`` drains pagination until skipToken is exhausted.
  * ``UnexpectedQueryExecutionError`` from ARG is translated into
    :class:`BatchTooComplex` so the caller can split the batch.
"""
from __future__ import annotations

import logging
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

from defender_pipeline.config import Config
from defender_pipeline.utils.batching import BatchTooComplex
from defender_pipeline.utils.retry import TransientARGError, arg_call_retry

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential

log = logging.getLogger("defender_pipeline.azure.resource_graph")


class ResourceGraphClient:
    """Thin wrapper around ``azure.mgmt.resourcegraph.ResourceGraphClient``.

    Exposes only ``run_query`` and ``iter_pages`` — the caller does not
    need to know about ``QueryRequest``/``QueryRequestOptions``.
    """

    def __init__(
        self,
        credential: TokenCredential,
        *,
        config: Config | None = None,
        subscription_ids: list[str] | None = None,
    ) -> None:
        from azure.mgmt.resourcegraph import ResourceGraphClient as _SdkClient
        # The SDK's enlatado default is 2021-03-01, under which
        # microsoft.security/cvedetails may omit exploitabilityDetails
        # and silently zero out exploit flags — pin to the validated
        # api-version from Config (2022-10-01).
        config = config or Config()
        self._client = _SdkClient(credential, api_version=config.arg_api_version)
        self._subscription_ids = subscription_ids
        self._page_size = config.arg_page_size

    @arg_call_retry
    def run_query(
        self,
        query: str,
        *,
        skip_token: str | None = None,
        top: int | None = None,
    ) -> dict[str, Any]:
        """Run a single ARG query. Returns a dict with keys ``data`` and
        (optional) ``skip_token`` for pagination. ``top`` defaults to
        the client's configured ``arg_page_size``."""
        from azure.core.exceptions import HttpResponseError
        from azure.mgmt.resourcegraph.models import (
            QueryRequest,
            QueryRequestOptions,
        )

        top = top if top is not None else self._page_size
        options = QueryRequestOptions(top=top, skip_token=skip_token) if skip_token else QueryRequestOptions(top=top)
        request = QueryRequest(
            query=query,
            options=options,
            subscriptions=self._subscription_ids,
        )
        try:
            response = self._client.resources(request)
        except HttpResponseError as exc:
            _translate_arg_error(exc)
            raise  # unreachable, _translate_arg_error always raises

        # response.data can be a list of dicts (default) or a table object
        # depending on the SDK version. Normalize to list-of-dicts.
        data = response.data if isinstance(response.data, list) else []
        result: dict[str, Any] = {
            "data": data,
            # Completeness signals from the ARG QueryResponse — see
            # ISSUE-002 (docs/ISSUES.md). iter_pages uses these to
            # validate that the drain actually matches the server's
            # declared row count. Each is defensively coerced: a
            # malformed / missing field must not raise here.
            "total_records": _coerce_total_records(
                getattr(response, "total_records", None),
            ),
            "count": _coerce_count(getattr(response, "count", None), data),
            "result_truncated": _normalise_truncated(
                getattr(response, "result_truncated", None),
            ),
        }
        skip = getattr(response, "skip_token", None)
        if skip:
            result["skip_token"] = skip
        return result

    def iter_pages(
        self, query: str, *, top: int | None = None,
        max_drain_retries: int = 2,
    ) -> Iterator[list[dict[str, Any]]]:
        """Drain all skip-token pages for a single query, validating
        completeness end-to-end. ``top`` defaults to the client's
        configured ``arg_page_size``.

        Completeness invariant (ISSUE-002, docs/ISSUES.md):

          * Collected row count must equal ``total_records`` from the
            first page (when the SDK provides it).
          * The final page must not have ``result_truncated=true``
            without a ``skip_token`` — that signals ARG stopped
            mid-stream and there is undetected loss.

        On divergence the whole drain is retried up to
        ``max_drain_retries`` times (default 2 → 3 total attempts).
        If divergence persists, :class:`CompletenessError` is raised
        and **no data is yielded** — the caller receives nothing,
        guaranteeing fail-closed behaviour (never emit a report that
        looks complete when it isn't).
        """
        last_error: CompletenessError | None = None
        for attempt in range(max_drain_retries + 1):
            try:
                pages = self._drain_once(query, top=top)
            except CompletenessError as exc:
                last_error = exc
                if attempt < max_drain_retries:
                    log.warning(
                        "iter_pages drain divergent on attempt %d/%d: %s",
                        attempt + 1, max_drain_retries + 1, exc,
                    )
                continue
            # Validated — safe to yield now.
            yield from pages
            return
        assert last_error is not None
        raise last_error

    def _drain_once(
        self, query: str, *, top: int | None,
    ) -> list[list[dict[str, Any]]]:
        """Drain pages into a buffered list, validating completeness
        AFTER all pages are received. Returns the page list on success;
        raises :class:`CompletenessError` on divergence. Never yields
        partial data to the caller — that's the outer ``iter_pages``
        contract."""
        skip: str | None = None
        pages: list[list[dict[str, Any]]] = []
        collected = 0
        expected: int | None = None
        final_truncated = False
        page_number = 0

        while True:
            page = self.run_query(query, skip_token=skip, top=top)
            page_number += 1
            data = page.get("data", [])
            pages.append(data)
            collected += len(data)
            if expected is None:
                # Lock in the server-declared total from the first page.
                expected = page.get("total_records")
            final_truncated = page.get("result_truncated", False)
            skip = page.get("skip_token")
            if not skip:
                break

        if final_truncated:
            raise CompletenessError(
                f"ARG returned result_truncated=true with no skip_token "
                f"after {page_number} page(s); collected={collected}, "
                f"total_records={expected} — silent loss",
            )
        if expected is not None and collected != expected:
            raise CompletenessError(
                f"collected {collected} rows but total_records={expected} "
                f"across {page_number} page(s) — silent loss",
            )
        return pages


class CompletenessError(Exception):
    """Raised by :meth:`ResourceGraphClient.iter_pages` when the drain
    cannot be reconciled against the ARG server-declared totals (see
    ISSUE-002 in ``docs/ISSUES.md``). The caller receives no data
    when this is raised — fail-closed by design."""


def _coerce_total_records(raw: Any) -> int | None:
    """Normalise total_records to int or None. Guards against SDK
    responses that omit the field (older versions) and against bool
    (which is a subclass of int and would be a nonsense value here)."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    return None


def _coerce_count(raw: Any, data: list[Any]) -> int:
    """Return the server-reported row count for this page, or fall back
    to the length of the normalised data list when the SDK didn't send
    one. Guards against older SDKs or malformed responses — a missing
    count must not break the completeness invariant."""
    if isinstance(raw, int):
        return raw
    return len(data)


def _normalise_truncated(raw: Any) -> bool:
    """Normalise the ARG ``result_truncated`` field (str 'true'/'false'
    or ``ResultTruncated`` enum) to a plain bool. Missing / unknown →
    False (treat as 'not truncated' so a missing field doesn't trigger
    false-positive truncation alarms)."""
    if raw is None:
        return False
    value = getattr(raw, "value", raw)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() == "true"


_TOO_COMPLEX_CODE = "UnexpectedQueryExecutionError"


def _has_too_complex_code(exc: Any) -> bool:
    """Return True if the SDK exception carries the
    ``UnexpectedQueryExecutionError`` code anywhere in the structured
    error payload. Walks ``exc.error.code`` and
    ``exc.error.details[*].code`` (each detail may be an ODataV4Format
    object or a plain dict).

    Falls back to a substring match on ``str(exc)`` so this still works
    if the SDK wraps the error differently in a future release.
    """
    error = getattr(exc, "error", None)
    if error is not None:
        if getattr(error, "code", None) == _TOO_COMPLEX_CODE:
            return True
        details = getattr(error, "details", None) or []
        for d in details:
            code = getattr(d, "code", None)
            if code is None and isinstance(d, dict):
                code = d.get("code")
            if code == _TOO_COMPLEX_CODE:
                return True
    # Last-resort fallback — guards against SDK re-wrapping or
    # localization that strips the structured payload.
    return _TOO_COMPLEX_CODE in str(exc)


def _translate_arg_error(exc: Any) -> None:
    """Translate an ARG SDK exception into our internal exception types.

    * ``UnexpectedQueryExecutionError`` (code in the structured error
      details) → :class:`BatchTooComplex` (caller splits the batch).
    * ``5xx`` / ``429`` / connection errors → :class:`TransientARGError`
      (retry decorator will retry).
    * Other 4xx (400 bad KQL, 403 auth) → let the original exception
      propagate (terminal — caller can't recover).
    """
    status = getattr(exc, "status_code", None)
    message = str(exc)
    # ARG returns HTTP 400 with top-level code "InternalServerError"
    # and a nested detail entry whose code is "UnexpectedQueryExecutionError"
    # when the query is too complex. Inspect the structured payload
    # first, then fall back to substring.
    if _has_too_complex_code(exc):
        raise BatchTooComplex(message) from exc
    if status in {429, 500, 502, 503, 504, 408}:
        raise TransientARGError(message) from exc
    # Terminal — let the SDK exception propagate as-is.
