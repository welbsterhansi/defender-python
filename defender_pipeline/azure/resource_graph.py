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
        subscription_ids: list[str] | None = None,
    ) -> None:
        from azure.mgmt.resourcegraph import ResourceGraphClient as _SdkClient
        self._client = _SdkClient(credential)
        self._subscription_ids = subscription_ids

    @arg_call_retry
    def run_query(
        self,
        query: str,
        *,
        skip_token: str | None = None,
        top: int = 1000,
    ) -> dict[str, Any]:
        """Run a single ARG query. Returns a dict with keys ``data`` and
        (optional) ``skip_token`` for pagination."""
        from azure.core.exceptions import HttpResponseError
        from azure.mgmt.resourcegraph.models import (
            QueryRequest,
            QueryRequestOptions,
        )

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
        result: dict[str, Any] = {"data": data}
        skip = getattr(response, "skip_token", None)
        if skip:
            result["skip_token"] = skip
        return result

    def iter_pages(self, query: str, *, top: int = 1000) -> Iterator[list[dict[str, Any]]]:
        """Drain all skip-token pages for a single query. Yields
        ``data`` list per page."""
        skip: str | None = None
        while True:
            page = self.run_query(query, skip_token=skip, top=top)
            yield page.get("data", [])
            skip = page.get("skip_token")
            if not skip:
                break


def _translate_arg_error(exc: Any) -> None:
    """Translate an ARG SDK exception into our internal exception types.

    * ``UnexpectedQueryExecutionError`` (in the error details) →
      :class:`BatchTooComplex` (caller splits the batch).
    * ``5xx`` / ``429`` / connection errors → :class:`TransientARGError`
      (retry decorator will retry).
    * Other 4xx (400 bad KQL, 403 auth) → let the original exception
      propagate (terminal — caller can't recover).
    """
    status = getattr(exc, "status_code", None)
    # ARG returns HTTP 400 with `code == "InternalServerError"` and a
    # detail entry with `code == "UnexpectedQueryExecutionError"` when
    # the query is too complex. Match on the substring.
    message = str(exc)
    if "UnexpectedQueryExecutionError" in message:
        raise BatchTooComplex(message) from exc
    if status in {429, 500, 502, 503, 504, 408}:
        raise TransientARGError(message) from exc
    # Terminal — let the SDK exception propagate as-is.
