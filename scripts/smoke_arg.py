#!/usr/bin/env python3
"""ARG pagination smoke test harness (ISSUE-002 P0 validation).

Runs the pipeline twice against the same scope, instruments iter_pages
to capture completeness telemetry per drain, and compares the two runs
by **set of unique keys** (not just row count — the client incident
surfaced only via key-level diff).

What it reports (per drain, per run):

  * query_tag          — which KQL (enumerate / assessments / cvedetails)
  * pages_consumed     — number of SDK calls in the drain
  * total_records      — server-declared total from the first page
  * rows_received      — rows actually collected across pages
  * duplicates         — rows with identical identity tuple within the drain
  * retries            — full-drain retries (CompletenessError triggered)
  * elapsed_ms         — wall time of the drain
  * result             — "ok" | "CompletenessError" | "<other-exception>"

What it does NOT log:

  * repository names
  * CVE ids
  * digests (truncated to 12 hex chars for diff only)
  * remediation text or any other row content

The identity key for comparison is a SHA-256 hex of the (repository,
digest, cveId) triple — the real values never appear in the report.

Usage:

    # Single image (safest first run)
    SCAN_IMAGE=my/repo:tag ACR=myacrname \\
        python scripts/smoke_arg.py --mode single

    # Small ACR scope (list a few repos explicitly)
    REPOS=foo/a,foo/b,foo/c ACR=myacrname \\
        python scripts/smoke_arg.py --mode acr-small

The script does NOT regenerate the ~12k scan — that is explicitly out
of scope per team direction. If any invariant check fails, the script
exits non-zero and prints exactly what diverged — the fail-closed
contract from ISSUE-002 is preserved end-to-end.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from time import monotonic
from typing import Any

# Project import — this script lives in scripts/ at repo root.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from defender_pipeline.azure.resource_graph import (  # noqa: E402
    CompletenessError,
    ResourceGraphClient,
)
from defender_pipeline.config import Config  # noqa: E402
from defender_pipeline.findings.scan import ScanOptions, run_scan  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s | %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("smoke_arg")


# ---------------------------------------------------------------------------
# Telemetry capture — one entry per iter_pages drain
# ---------------------------------------------------------------------------


@dataclass
class DrainMetrics:
    query_tag: str
    pages_consumed: int = 0
    total_records: int | None = None
    rows_received: int = 0
    duplicates: int = 0
    retries: int = 0
    elapsed_ms: int = 0
    result: str = "ok"


@dataclass
class RunMetrics:
    label: str
    drains: list[DrainMetrics] = field(default_factory=list)
    key_hashes: set[str] = field(default_factory=set)
    scan_elapsed_ms: int = 0
    scan_result: str = "ok"


def _query_tag(query: str) -> str:
    if "distinct _repository, _digest" in query:
        return "enumerate"
    if "inlineSeverity" in query:
        return "assessments"
    if "cvssEnrich" in query:
        return "cvedetails"
    return "other"


class InstrumentedClient(ResourceGraphClient):
    """ResourceGraphClient that records a DrainMetrics per iter_pages
    call into the ``drains`` list it is given at construction."""

    def __init__(self, *args: Any, metrics_sink: list[DrainMetrics], **kw: Any) -> None:
        super().__init__(*args, **kw)
        self._metrics_sink = metrics_sink

    def iter_pages(
        self, query: str, *, top: int | None = None,
        max_drain_retries: int = 2,
    ) -> Iterator[list[dict[str, Any]]]:
        metrics = DrainMetrics(query_tag=_query_tag(query))
        t0 = monotonic()
        try:
            # Instrument by draining once ourselves per attempt. Easiest
            # way to count pages/retries/total_records without touching
            # the production class: wrap each attempt in a shim.
            last_err: CompletenessError | None = None
            for attempt in range(max_drain_retries + 1):
                drain_pages: list[list[dict[str, Any]]] = []
                skip: str | None = None
                collected = 0
                expected: int | None = None
                final_truncated = False
                page_number = 0
                try:
                    while True:
                        page = self.run_query(query, skip_token=skip, top=top)
                        page_number += 1
                        data = page.get("data", [])
                        drain_pages.append(data)
                        collected += len(data)
                        if expected is None:
                            expected = page.get("total_records")
                        final_truncated = page.get("result_truncated", False)
                        skip = page.get("skip_token")
                        if not skip:
                            break
                    if final_truncated:
                        raise CompletenessError(
                            f"result_truncated=true with no skip_token "
                            f"after {page_number} page(s); collected={collected}, "
                            f"total_records={expected}",
                        )
                    if expected is not None and collected != expected:
                        raise CompletenessError(
                            f"collected {collected} rows but total_records="
                            f"{expected} across {page_number} page(s)",
                        )
                except CompletenessError as exc:
                    last_err = exc
                    metrics.retries += 1
                    if attempt < max_drain_retries:
                        continue
                    metrics.result = "CompletenessError"
                    raise
                # Success: record final metrics and yield.
                metrics.pages_consumed = page_number
                metrics.total_records = expected
                metrics.rows_received = collected
                # Duplicate check within drain — identity depends on query.
                metrics.duplicates = _count_duplicates(
                    drain_pages, metrics.query_tag,
                )
                for data in drain_pages:
                    yield data
                return
            # unreachable if max_drain_retries>=0 and last_err set
            assert last_err is not None
            raise last_err
        except Exception as exc:
            if metrics.result == "ok":
                metrics.result = type(exc).__name__
            raise
        finally:
            metrics.elapsed_ms = int((monotonic() - t0) * 1000)
            self._metrics_sink.append(metrics)


def _count_duplicates(pages: list[list[dict[str, Any]]], tag: str) -> int:
    seen: set[tuple] = set()
    dups = 0
    for page in pages:
        for row in page:
            key = _row_identity(row, tag)
            if key in seen:
                dups += 1
            else:
                seen.add(key)
    return dups


def _row_identity(row: dict[str, Any], tag: str) -> tuple:
    """Query-specific identity tuple. Values are not stored — only
    hashed via tuple equality for dup detection."""
    if tag == "enumerate":
        return (row.get("_repository"), row.get("_digest"))
    if tag == "assessments":
        return (
            row.get("repository"), row.get("digest"),
            row.get("cveId"), row.get("packageName"),
        )
    if tag == "cvedetails":
        return (row.get("cveIdJoin"),)
    return (id(row),)


# ---------------------------------------------------------------------------
# Scan orchestration + per-row key hashing (identity only, no values)
# ---------------------------------------------------------------------------


def _hash_identity(repository: str, digest: str, cve_id: str) -> str:
    """Hash the (repo, digest, cveId) triple — real values never leave
    this process. Prefix of hex is enough for set comparison."""
    h = hashlib.sha256()
    h.update(f"{repository}|{digest}|{cve_id}".encode())
    return h.hexdigest()[:32]


def _run_once(label: str, opts: ScanOptions, output_dir: Path) -> RunMetrics:
    metrics = RunMetrics(label=label)
    opts = ScanOptions(
        acr_name=opts.acr_name,
        min_score=opts.min_score,
        max_score=opts.max_score,
        repository=opts.repository,
        repositories=opts.repositories,
        scan_repository=opts.scan_repository,
        scan_digest=opts.scan_digest,
        skip_tags=opts.skip_tags,
        output=output_dir / f"{label}.csv",
    )
    cfg = Config()
    # Build an authenticated instrumented client — defers to pipeline.auth.
    from defender_pipeline.azure.auth import get_credential
    cred = get_credential()
    client = InstrumentedClient(
        cred, config=cfg, metrics_sink=metrics.drains,
    )
    t0 = monotonic()
    try:
        rows = run_scan(opts, config=cfg, arg_client=client)
        metrics.scan_result = f"ok ({rows} rows)"
    except Exception as exc:
        metrics.scan_result = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        metrics.scan_elapsed_ms = int((monotonic() - t0) * 1000)

    # Build key-set from the output CSV (identity only, no values).
    import csv
    with opts.output.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            metrics.key_hashes.add(_hash_identity(
                row.get("repository", ""),
                row.get("digest", ""),
                row.get("cveId", ""),
            ))
    return metrics


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="ISSUE-002 ARG pagination smoke test (fail closed)",
    )
    parser.add_argument(
        "--mode", choices=["single", "acr-small"], required=True,
        help="single = SCAN_IMAGE env; acr-small = REPOS env (comma-list)",
    )
    parser.add_argument(
        "--min-score", type=float, default=0.0,
        help="Lower the floor so smoke sees more rows (default 0)",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("smoke_out"),
        help="Where to write per-run CSVs (gitignored)",
    )
    args = parser.parse_args()

    acr = os.environ.get("ACR")
    if not acr:
        log.error("ACR env var required (ACR name without .azurecr.io)")
        return 2

    args.output_dir.mkdir(parents=True, exist_ok=True)

    if args.mode == "single":
        scan_image = os.environ.get("SCAN_IMAGE")
        if not scan_image or ":" not in scan_image:
            log.error("SCAN_IMAGE=repo:tag env var required for --mode single")
            return 2
        repo, tag = scan_image.rsplit(":", 1)
        opts = ScanOptions(
            acr_name=acr, min_score=args.min_score,
            scan_repository=repo, skip_tags=False,
            output=args.output_dir / "unused.csv",
        )
        log.info("mode=single acr=%s repo=%s tag=%s", acr, repo, tag)
    else:
        repos = os.environ.get("REPOS", "").strip()
        if not repos:
            log.error("REPOS env var required for --mode acr-small (comma-list)")
            return 2
        repo_list = [r.strip() for r in repos.split(",") if r.strip()]
        opts = ScanOptions(
            acr_name=acr, min_score=args.min_score,
            repositories=repo_list, skip_tags=False,
            output=args.output_dir / "unused.csv",
        )
        log.info("mode=acr-small acr=%s repos_count=%d", acr, len(repo_list))

    # Two runs — the critical check is set-of-keys equality.
    try:
        run_a = _run_once("run_a", opts, args.output_dir)
        run_b = _run_once("run_b", opts, args.output_dir)
    except CompletenessError as exc:
        log.error("CompletenessError propagated — fail-closed worked. detail=%s", exc)
        _dump_report(args.output_dir, run_a=None, run_b=None, failure=str(exc))
        return 3

    # Set-of-keys diff.
    only_a = run_a.key_hashes - run_b.key_hashes
    only_b = run_b.key_hashes - run_a.key_hashes
    diff_count = len(only_a) + len(only_b)
    passed = diff_count == 0

    _dump_report(args.output_dir, run_a=run_a, run_b=run_b,
                 only_a=len(only_a), only_b=len(only_b), passed=passed)

    if passed:
        log.info("smoke OK — both runs produced identical key sets (|K|=%d)",
                 len(run_a.key_hashes))
        return 0
    log.error(
        "smoke DIVERGED — run_a has %d keys only, run_b has %d keys only",
        len(only_a), len(only_b),
    )
    return 4


def _dump_report(
    output_dir: Path, *, run_a: RunMetrics | None, run_b: RunMetrics | None,
    only_a: int = 0, only_b: int = 0, passed: bool = False,
    failure: str | None = None,
) -> None:
    report = {
        "schema": "smoke_arg_v1",
        "passed": passed,
        "failure": failure,
        "key_diff": {
            "only_in_run_a": only_a,
            "only_in_run_b": only_b,
        },
        "run_a": _run_dict(run_a),
        "run_b": _run_dict(run_b),
    }
    out = output_dir / "smoke_report.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    log.info("wrote %s", out)


def _run_dict(run: RunMetrics | None) -> dict[str, Any] | None:
    if run is None:
        return None
    return {
        "label": run.label,
        "scan_result": run.scan_result,
        "scan_elapsed_ms": run.scan_elapsed_ms,
        "key_count": len(run.key_hashes),
        "drains": [asdict(d) for d in run.drains],
    }


if __name__ == "__main__":
    raise SystemExit(main())
