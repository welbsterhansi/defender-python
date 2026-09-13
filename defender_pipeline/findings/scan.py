"""Scan orchestrator — Python port of the P2 batched flow in ``defender.sh``.

Phases (same as the bash implementation):

    0. Enumerate unique (repository, digest) pairs.
    1. Resolve tags upfront (one call per unique repo, unless --skip-tags).
    2a. Batched assessments query (no JOIN, ~50 digests per call).
    2b. Extract unique CVE IDs from the assessments rows.
    2c. Batched cvedetails query (~500 CVE IDs per call).
    2d. Local merge via :mod:`findings.enrich`.
    2e. Write final CSV with 19 columns via :mod:`utils.csvio`.

Failure mode: :class:`utils.batching.BatchTooComplex` from ARG is
handled by the batch-split runner (halves recursively). Terminal
failures propagate to the CLI which returns non-zero.
"""
from __future__ import annotations

import logging
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from time import monotonic

from defender_pipeline.azure.acr import AcrTagResolver
from defender_pipeline.azure.auth import get_credential
from defender_pipeline.azure.queries import (
    build_batched_assessments_query,
    build_batched_cvedetails_query,
    build_enumerate_digests_query,
    build_scope_filter,
)
from defender_pipeline.azure.resource_graph import ResourceGraphClient
from defender_pipeline.config import Config
from defender_pipeline.findings.csv_contracts import (
    VULNERABLE_IMAGES_HEADER_COLUMNS,
)
from defender_pipeline.findings.enrich import merge
from defender_pipeline.findings.models import (
    AssessmentRow,
    DigestPair,
    EnrichmentRow,
    Finding,
)
from defender_pipeline.utils.batching import run_batched_with_split
from defender_pipeline.utils.csvio import csv_field, csv_write_row

log = logging.getLogger("defender_pipeline.findings.scan")


def _progress(msg: str) -> None:
    """Live per-batch progress line — bypasses logger buffering so
    operators SEE where a long scan is right now, matching
    ``defender.sh`` style ``[assessments batch N] digests X..Y of Z``.
    Sent to stderr with flush so it appears immediately even when
    stdout is redirected to a file."""
    print(msg, file=sys.stderr, flush=True)


def _fmt_elapsed(seconds: float) -> str:
    """Compact ``Xm Ys`` for the progress lines."""
    m, s = divmod(int(seconds), 60)
    return f"{m}m{s:02d}s" if m else f"{s}s"


@dataclass(frozen=True, slots=True)
class ScanOptions:
    acr_name: str
    min_score: float = 9.0
    max_score: float = 10.0
    repository: str | None = None
    repositories: Sequence[str] | None = None
    scan_repository: str | None = None
    scan_digest: str | None = None
    skip_tags: bool = False
    output: Path = Path("vulnerable_images_report.csv")


def run_scan(
    opts: ScanOptions,
    *,
    config: Config | None = None,
    arg_client: ResourceGraphClient | None = None,
    tag_resolver: AcrTagResolver | None = None,
) -> int:
    """Execute a full report-only scan. Returns the count of rows emitted.

    Injectable ``arg_client`` and ``tag_resolver`` for testing.
    """
    config = config or Config()
    credential = None  # lazy — only created if we need to build a client
    if arg_client is None:
        credential = get_credential()
        arg_client = ResourceGraphClient(credential)
    if tag_resolver is None and not opts.skip_tags:
        credential = credential or get_credential()
        tag_resolver = AcrTagResolver(credential, opts.acr_name)

    t_scan_start = monotonic()
    scope_desc = _describe_scope(opts)
    _progress(
        f"=== scan start: acr={opts.acr_name} score={opts.min_score}..{opts.max_score} "
        f"scope={scope_desc} skip_tags={opts.skip_tags} ===",
    )

    # ── PHASE 0: enumerate ───────────────────────────────────────────
    filter_kql = build_scope_filter(
        repository=opts.repository,
        repositories=opts.repositories,
        scan_repository=opts.scan_repository,
        scan_digest=opts.scan_digest,
    )
    t0 = monotonic()
    _progress("[phase 0/2] enumerate digests ...")
    digest_pairs = _phase0_enumerate(arg_client, filter_kql)
    _progress(
        f"[phase 0/2] enumerate: {len(digest_pairs)} unique (repo,digest) "
        f"pairs, elapsed={_fmt_elapsed(monotonic() - t0)}",
    )
    log.info(
        "enumerate: found %d unique pairs time_ms=%d",
        len(digest_pairs), int((monotonic() - t0) * 1000),
    )

    if not digest_pairs:
        _write_csv([], opts.output)
        _progress(
            f"=== scan end: 0 rows (no digests found), "
            f"total={_fmt_elapsed(monotonic() - t_scan_start)} ===",
        )
        log.info(
            "end total_processed=0 digests=0 report_file=%s", opts.output,
        )
        return 0

    # ── PHASE 1: tag_resolve ─────────────────────────────────────────
    tag_cache: dict[str, str] = {}
    if opts.skip_tags:
        _progress("[phase 1/2] tag_resolve SKIPPED (--skip-tags, tag=N/A)")
        log.info("tag_resolve DISABLED via --skip-tags (all rows will have tag=N/A)")
    else:
        assert tag_resolver is not None
        t1 = monotonic()
        unique_repos = sorted({p.repository for p in digest_pairs})
        _progress(
            f"[phase 1/2] tag_resolve: {len(unique_repos)} unique repo(s) ...",
        )
        log.info("tag_resolve: start unique_repos=%d", len(unique_repos))
        tag_resolver.resolve_repos(unique_repos)
        tag_cache = tag_resolver.tag_cache
        _progress(
            f"[phase 1/2] tag_resolve: {len(unique_repos) - len(tag_resolver.failed_repos)} "
            f"resolved, {len(tag_resolver.failed_repos)} failed, "
            f"elapsed={_fmt_elapsed(monotonic() - t1)}",
        )
        log.info(
            "tag_resolve: end api_calls=%d cached_pairs=%d time_ms=%d",
            len(unique_repos) - len(tag_resolver.failed_repos),
            len(tag_cache),
            int((monotonic() - t1) * 1000),
        )

    # ── PHASE 2a: batched assessments ────────────────────────────────
    digests = [p.digest for p in digest_pairs]
    t2a = monotonic()
    total_a_batches = _estimate_batches(len(digests), config.assessments_batch_size)
    _progress(
        f"[phase 2a/2] assessments: {len(digests)} digests in ~{total_a_batches} "
        f"batch(es) of {config.assessments_batch_size} ...",
    )
    log.info(
        "phase2a assessments_batched: start batch_size=%d pairs=%d",
        config.assessments_batch_size, len(digests),
    )
    assessments = _phase2a_batched_assessments(
        arg_client, digests, config.assessments_batch_size,
        t_start=t2a, total_batches=total_a_batches,
    )
    _progress(
        f"[phase 2a/2] assessments: {len(assessments)} row(s) collected, "
        f"elapsed={_fmt_elapsed(monotonic() - t2a)}",
    )
    log.info(
        "phase2a assessments_batched: end rows=%d time_ms=%d",
        len(assessments), int((monotonic() - t2a) * 1000),
    )

    # ── PHASE 2b: unique CVE IDs ─────────────────────────────────────
    t2b = monotonic()
    unique_cves = sorted({a.cve_id.upper() for a in assessments if a.cve_id.startswith("CVE-")})
    _progress(f"[phase 2b/2] extract_cves: {len(unique_cves)} unique CVE ID(s)")
    log.info(
        "phase2b extract_cves: unique_cves=%d time_ms=%d",
        len(unique_cves), int((monotonic() - t2b) * 1000),
    )

    # ── PHASE 2c: batched cvedetails ─────────────────────────────────
    enrichment_by_cve: dict[str, EnrichmentRow] = {}
    if unique_cves:
        t2c = monotonic()
        total_c_batches = _estimate_batches(len(unique_cves), config.cvedetails_batch_size)
        _progress(
            f"[phase 2c/2] cvedetails: {len(unique_cves)} CVE(s) in ~{total_c_batches} "
            f"batch(es) of {config.cvedetails_batch_size} ...",
        )
        log.info(
            "phase2c cvedetails_batched: start batch_size=%d",
            config.cvedetails_batch_size,
        )
        enrichment_rows = _phase2c_batched_cvedetails(
            arg_client, unique_cves, config.cvedetails_batch_size,
            t_start=t2c, total_batches=total_c_batches,
        )
        for e in enrichment_rows:
            enrichment_by_cve[e.cve_id_join] = e
        _progress(
            f"[phase 2c/2] cvedetails: {len(enrichment_rows)} enrichment row(s), "
            f"elapsed={_fmt_elapsed(monotonic() - t2c)}",
        )
        log.info(
            "phase2c cvedetails_batched: end rows=%d time_ms=%d",
            len(enrichment_rows), int((monotonic() - t2c) * 1000),
        )
    else:
        _progress("[phase 2c/2] cvedetails: SKIPPED (no CVE IDs)")

    # ── PHASE 2d + 2e: merge + write CSV ─────────────────────────────
    t2d = monotonic()
    _progress("[phase 2d/2] merge + write ...")
    findings = merge(
        assessments,
        enrichment_by_cve,
        tag_cache,
        min_score=opts.min_score,
        max_score=opts.max_score,
    )
    _write_csv(findings, opts.output)
    log.info(
        "phase2d merge: rows_read=%d rows_emitted=%d rows_enriched=%d "
        "cvedetails_keys=%d time_ms=%d",
        len(assessments), len(findings),
        sum(1 for a in assessments if a.cve_id.upper() in enrichment_by_cve),
        len(enrichment_by_cve),
        int((monotonic() - t2d) * 1000),
    )
    _progress(
        f"=== scan end: {len(findings)} row(s) written to {opts.output}, "
        f"total={_fmt_elapsed(monotonic() - t_scan_start)} ===",
    )
    log.info(
        "end total_processed=%d digests=%d report_file=%s",
        len(findings), len(digest_pairs), opts.output,
    )
    return len(findings)


# ---------------------------------------------------------------------------
# Phase helpers
# ---------------------------------------------------------------------------


def _phase0_enumerate(
    client: ResourceGraphClient, filter_kql: str,
) -> list[DigestPair]:
    kql = build_enumerate_digests_query(filter_kql)
    pairs: list[DigestPair] = []
    for page in client.iter_pages(kql):
        for row in page:
            repo = str(row.get("_repository") or "")
            digest = str(row.get("_digest") or "")
            if repo and digest:
                pairs.append(DigestPair(repository=repo, digest=digest))
    # Dedup (KQL emits distinct but be defensive across pages)
    seen: set[tuple[str, str]] = set()
    unique: list[DigestPair] = []
    for pair in pairs:
        key = (pair.repository, pair.digest)
        if key in seen:
            continue
        seen.add(key)
        unique.append(pair)
    return unique


def _phase2a_batched_assessments(
    client: ResourceGraphClient,
    digests: Sequence[str],
    batch_size: int,
    *,
    t_start: float | None = None,
    total_batches: int | None = None,
) -> list[AssessmentRow]:
    batch_num = [0]  # closure counter (list for py mutability)

    def _on_batch(start: int, end: int, total: int) -> None:
        batch_num[0] += 1
        elapsed = _fmt_elapsed(monotonic() - t_start) if t_start else "?"
        _progress(
            f"  [assessments batch {batch_num[0]}/{total_batches or '?'}] "
            f"digests {start}..{end} of {total} elapsed={elapsed}",
        )

    def _run_one_batch(chunk: Sequence[str]) -> list[AssessmentRow]:
        kql = build_batched_assessments_query(chunk)
        rows: list[AssessmentRow] = []
        for page in client.iter_pages(kql):
            rows.extend(AssessmentRow.from_arg_row(row) for row in page)
        return rows

    return run_batched_with_split(
        digests, _run_one_batch, initial_batch_size=batch_size,
        on_batch_start=_on_batch,
    )


def _phase2c_batched_cvedetails(
    client: ResourceGraphClient,
    cve_ids: Sequence[str],
    batch_size: int,
    *,
    t_start: float | None = None,
    total_batches: int | None = None,
) -> list[EnrichmentRow]:
    batch_num = [0]

    def _on_batch(start: int, end: int, total: int) -> None:
        batch_num[0] += 1
        elapsed = _fmt_elapsed(monotonic() - t_start) if t_start else "?"
        _progress(
            f"  [cvedetails batch {batch_num[0]}/{total_batches or '?'}] "
            f"CVE IDs {start}..{end} of {total} elapsed={elapsed}",
        )

    def _run_one_batch(chunk: Sequence[str]) -> list[EnrichmentRow]:
        kql = build_batched_cvedetails_query(chunk)
        rows: list[EnrichmentRow] = []
        for page in client.iter_pages(kql):
            rows.extend(EnrichmentRow.from_arg_row(row) for row in page)
        return rows

    return run_batched_with_split(
        cve_ids, _run_one_batch, initial_batch_size=batch_size,
        on_batch_start=_on_batch,
    )


def _estimate_batches(items: int, batch_size: int) -> int:
    """Ceil-div estimate; actual count may be higher due to splits."""
    if batch_size <= 0:
        return 0
    return (items + batch_size - 1) // batch_size


def _describe_scope(opts: ScanOptions) -> str:
    if opts.scan_repository:
        return f"scan-image={opts.scan_repository}" + (
            f"@{opts.scan_digest}" if opts.scan_digest else ""
        )
    if opts.repositories:
        return f"repositories={len(list(opts.repositories))} exact"
    if opts.repository:
        return f"repository=contains({opts.repository!r})"
    return "all"


# ---------------------------------------------------------------------------
# CSV writer — reuses the bash-compat csv_field / csv_write_row
# ---------------------------------------------------------------------------


def _write_csv(findings: Sequence[Finding], path: Path) -> None:
    """Write findings to a CSV using the bash-compat quoting."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        # Header — same format as `echo '"col","col"...' > $REPORT_TMP`
        header_line = ",".join(csv_field(c) for c in VULNERABLE_IMAGES_HEADER_COLUMNS)
        f.write(header_line + "\n")
        for finding in findings:
            csv_write_row(f, finding.as_csv_values())
