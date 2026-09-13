"""Cluster subcommand orchestrator.

Ties together the OpenShift modules with ``group_findings.group_rows``
to produce ``resultado_cruzamento.csv`` — matching the frozen contract
in ``docs/contracts/resultado_cruzamento.md``.

Reuses ``group_findings.group_rows()`` verbatim (it's already a plain
Python function with unit tests). No duplication.
"""
from __future__ import annotations

import csv
import logging
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from defender_pipeline.openshift.client import get_core_api
from defender_pipeline.openshift.correlate import (
    correlate,
    load_cve_csv_by_digest,
)
from defender_pipeline.openshift.coverage import (
    Coverage,
    exit_code_for,
    summarize,
)

log = logging.getLogger("defender_pipeline.openshift.cluster")


@dataclass(frozen=True, slots=True)
class ClusterOptions:
    vulnerabilities: Path = Path("vulnerable_images_report.csv")
    output: Path = Path("resultado_cruzamento.csv")
    kubeconfig: Path | None = None


def run_cluster(opts: ClusterOptions) -> int:
    """Execute the cluster cross-reference. Returns the CLI exit code.

    Exit codes (frozen contract):
      * ``0`` — COMPLETE (every visited namespace was OK or empty)
      * ``3`` — PARTIAL (at least one namespace failed)
    """
    if not opts.vulnerabilities.exists():
        log.error("cluster: vulnerabilities CSV not found: %s", opts.vulnerabilities)
        return 1

    cve_by_digest = load_cve_csv_by_digest(opts.vulnerabilities)
    log.info("cluster: loaded %d unique digests from CVE CSV", len(cve_by_digest))

    api = get_core_api(opts.kubeconfig)
    result = correlate(api, cve_by_digest)

    coverage = summarize(result.states)
    _log_coverage_summary(result, coverage)

    # Write CSV — reuse the same aggregator the bash pipeline uses.
    _write_grouped_csv(result.flat_rows, opts.output)

    return exit_code_for(coverage)


def _log_coverage_summary(result, coverage: Coverage) -> None:
    counts = Counter(r.state.value for r in result.reports)
    log.info(
        "coverage: analyzed=%d no_pods=%d rbac_err=%d oc_err=%d parse_err=%d "
        "pods=%d matches=%d overall=%s",
        counts.get("SUCCESS_WITH_PODS", 0),
        counts.get("NO_PODS", 0),
        counts.get("RBAC_ERR", 0),
        counts.get("OC_ERR", 0),
        counts.get("PARSE_ERR", 0),
        result.total_pods, result.total_matches, coverage.value,
    )


def _write_grouped_csv(flat_rows: list[dict[str, str]], output: Path) -> None:
    """Group flat rows and write the 24-column CSV.

    Delegates to ``group_findings.group_rows`` — the same function
    ``check_ocp.sh`` invokes via ``group_findings.py``. Guarantees
    byte-identical output between the two paths.

    Deterministic sort applied before write: rows come out of the
    cluster in Kubernetes list order (not stable across API calls) —
    sort so diff/tests/downstream consumption is predictable across
    runs. Sort order matches the natural grouping hierarchy:
    NAMESPACE → PARENT_TYPE → PARENT_NAME → REPOSITORY → DIGEST.
    """
    from defender_pipeline.openshift._group_findings import OUTPUT_HEADER, group_rows

    output.parent.mkdir(parents=True, exist_ok=True)
    grouped = group_rows(flat_rows)

    # OUTPUT_HEADER col indices: 0=NAMESPACE, 1=PARENT_TYPE,
    # 2=PARENT_NAME, 3=REPOSITORY, 4=DIGEST
    grouped.sort(key=lambda r: (r[0], r[1], r[2], r[3], r[4]))

    csv.field_size_limit(2**24)
    with output.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(OUTPUT_HEADER)
        writer.writerows(grouped)
    log.info("cluster: wrote %d groups to %s", len(grouped), output)
