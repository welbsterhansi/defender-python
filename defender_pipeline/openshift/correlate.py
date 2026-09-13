"""Workloads × images cross-reference — Python port of ``check_ocp.sh``.

Per namespace:
  * List pods via the Kubernetes client.
  * Walk ``ownerReferences`` up to the workload controller
    (Deployment / StatefulSet / DaemonSet / Job / Pod-fallback), applying
    the same suffix-strip normalization the bash pipeline uses:
      - ``ReplicationController "app-N"`` → ``DeploymentConfig "app"``
      - ``ReplicaSet "app-abc123"``       → ``Deployment "app"``
  * Extract image digests from ``containerStatuses[].imageID`` (matches
    ``sha256:[a-f0-9]{64}``).
  * For each matching digest, emit one flat row per matched CVE.

Coverage classification (frozen, mirrors ``check_ocp.sh`` and
``docs/contracts/resultado_cruzamento.md``):

  * SUCCESS_WITH_PODS — namespace listed pods and at least one pod found.
  * NO_PODS           — namespace listed successfully, zero pods.
  * RBAC_ERR          — HTTP 403 from ``list_namespaced_pod``.
  * OC_ERR            — non-403 API error.
  * PARSE_ERR         — data received but could not be interpreted.
"""
from __future__ import annotations

import csv
import logging
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from defender_pipeline.openshift.coverage import CoverageState
from defender_pipeline.openshift.csv_contracts import EXCLUDED_NAMESPACE_PATTERNS

if TYPE_CHECKING:
    from kubernetes.client import CoreV1Api

log = logging.getLogger("defender_pipeline.openshift.correlate")

# Digest regex — matches ``sha256:<64 hex>``. imageID may prefix with
# ``docker-pullable://<repo>@`` or come as ``<registry>/<repo>@<sha256:...>``.
_DIGEST_RE = re.compile(r"sha256:[a-f0-9]{64}")

_REPLICASET_SUFFIX = re.compile(r"-[a-z0-9]+$")
_REPLICATIONCONTROLLER_SUFFIX = re.compile(r"-[0-9]+$")


@dataclass(slots=True)
class NamespaceReport:
    """Per-namespace outcome — used to build the coverage summary."""

    name: str
    state: CoverageState
    pod_count: int = 0
    match_count: int = 0
    error_detail: str = ""


@dataclass(slots=True)
class CorrelationResult:
    """Aggregate outcome of the whole cross-reference run."""

    flat_rows: list[dict[str, str]] = field(default_factory=list)
    reports: list[NamespaceReport] = field(default_factory=list)

    @property
    def states(self) -> list[CoverageState]:
        return [r.state for r in self.reports]

    @property
    def total_pods(self) -> int:
        return sum(r.pod_count for r in self.reports)

    @property
    def total_matches(self) -> int:
        return sum(r.match_count for r in self.reports)


# ---------------------------------------------------------------------------
# CVE CSV loader — index by digest so lookup is O(1).
# ---------------------------------------------------------------------------


def load_cve_csv_by_digest(path: Path) -> dict[str, list[dict[str, str]]]:
    """Load ``vulnerable_images_report.csv`` into a dict keyed by digest.

    Each digest maps to the LIST of CSV rows carrying that digest — a
    single digest usually has one row per CVE.
    """
    by_digest: dict[str, list[dict[str, str]]] = defaultdict(list)
    csv.field_size_limit(2**24)
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            digest = (row.get("digest") or "").strip()
            if digest:
                by_digest[digest].append(row)
    return by_digest


# ---------------------------------------------------------------------------
# Namespace enumeration + filter
# ---------------------------------------------------------------------------


def list_target_namespaces(api: CoreV1Api) -> list[str]:
    """Return all namespaces minus the platform-managed ones.

    The exclusion list is frozen in
    ``defender_pipeline.openshift.csv_contracts.EXCLUDED_NAMESPACE_PATTERNS``.
    """
    ns_list = api.list_namespace()
    all_names = [ns.metadata.name for ns in ns_list.items if ns.metadata and ns.metadata.name]
    return [n for n in all_names if not _is_platform_namespace(n)]


def _is_platform_namespace(name: str) -> bool:
    for pattern in EXCLUDED_NAMESPACE_PATTERNS:
        # Exact match for literals like "default" / "logging" / "monitoring".
        # Prefix match for wildcards like "openshift-" / "kube-".
        if pattern.endswith("-"):
            if name.startswith(pattern):
                return True
        elif name == pattern:
            return True
    return False


# ---------------------------------------------------------------------------
# Per-pod extraction
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class PodImage:
    """One (workload, image-digest) tuple extracted from a pod."""

    namespace: str
    parent_kind: str
    parent_name: str
    digest: str


def _resolve_parent(pod: Any) -> tuple[str, str]:
    """Return the (kind, name) of the workload controller for this pod.

    Applies the same suffix-strip normalization as ``check_ocp.sh``:
    ReplicaSet → Deployment (drop ``-<hash>``), ReplicationController-N →
    DeploymentConfig (drop ``-<n>``).
    """
    meta = pod.metadata
    owners = meta.owner_references if (meta and meta.owner_references) else []
    if not owners:
        return ("Pod", meta.name if meta else "")
    owner = owners[0]
    kind = owner.kind or "Pod"
    name = owner.name or (meta.name if meta else "")

    if kind == "ReplicationController":
        m = _REPLICATIONCONTROLLER_SUFFIX.search(name)
        if m:
            return ("DeploymentConfig", name[: m.start()])
    elif kind == "ReplicaSet":
        m = _REPLICASET_SUFFIX.search(name)
        if m:
            return ("Deployment", name[: m.start()])
    return (kind, name)


def _extract_image_digests(pod: Any) -> list[str]:
    """Extract every ``sha256:<hex>`` present in the pod's container image IDs.

    Reads both ``status.container_statuses[].image_id`` and
    ``status.init_container_statuses[].image_id`` (initContainers may
    carry independent vulnerable base images).
    """
    if not pod.status:
        return []
    digests: list[str] = []
    for statuses in (
        pod.status.container_statuses or [],
        pod.status.init_container_statuses or [],
    ):
        for cs in statuses:
            image_id = getattr(cs, "image_id", "") or ""
            m = _DIGEST_RE.search(image_id)
            if m:
                digests.append(m.group(0))
    return digests


def _process_and_emit(
    api: CoreV1Api,
    namespace: str,
    cve_by_digest: dict[str, list[dict[str, str]]],
    flat_rows: list[dict[str, str]],
) -> NamespaceReport:
    """Analyze a namespace and append matched CVE rows to ``flat_rows``.

    Returns the classification report for coverage aggregation.
    """
    from kubernetes.client.exceptions import ApiException

    try:
        pod_list = api.list_namespaced_pod(namespace=namespace)
    except ApiException as exc:
        status = exc.status
        if status == 403:
            log.warning(
                "namespace=%s RBAC_ERR — grant get/list pods or exclude from filter",
                namespace,
            )
            return NamespaceReport(
                namespace, CoverageState.RBAC_ERR,
                error_detail=f"HTTP 403: {exc.reason}",
            )
        log.warning("namespace=%s OC_ERR — %s %s", namespace, status, exc.reason)
        return NamespaceReport(
            namespace, CoverageState.OC_ERR,
            error_detail=f"HTTP {status}: {exc.reason}",
        )
    except Exception as exc:  # — defensive; PARSE_ERR class
        log.warning("namespace=%s PARSE_ERR — %s", namespace, exc)
        return NamespaceReport(
            namespace, CoverageState.PARSE_ERR, error_detail=str(exc),
        )

    pods = pod_list.items or []
    if not pods:
        return NamespaceReport(namespace, CoverageState.NO_PODS)

    match_count = 0
    for pod in pods:
        try:
            parent_kind, parent_name = _resolve_parent(pod)
            digests = _extract_image_digests(pod)
        except Exception as exc:  # — one pod's oddity shouldn't kill the whole ns
            log.warning("namespace=%s pod=%s parse issue: %s",
                        namespace, getattr(pod.metadata, "name", "?"), exc)
            continue

        for digest in digests:
            cve_rows = cve_by_digest.get(digest, [])
            if not cve_rows:
                continue
            for cve_row in cve_rows:
                match_count += 1
                # Compose the flat row shape check_ocp.sh emits — keys
                # must match group_findings.group_rows() expectations.
                flat_rows.append({
                    "NAMESPACE": namespace,
                    "PARENT_TYPE": parent_kind,
                    "PARENT_NAME": parent_name,
                    **cve_row,
                })

    return NamespaceReport(
        namespace, CoverageState.SUCCESS_WITH_PODS,
        pod_count=len(pods), match_count=match_count,
    )


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------


def correlate(
    api: CoreV1Api,
    cve_by_digest: dict[str, list[dict[str, str]]],
    *,
    namespaces: Iterable[str] | None = None,
) -> CorrelationResult:
    """Cross-reference cluster workloads with CVE CSV rows.

    Args:
        api: an authenticated ``CoreV1Api`` (from
            :func:`defender_pipeline.openshift.client.get_core_api`).
        cve_by_digest: output of :func:`load_cve_csv_by_digest`.
        namespaces: optional explicit list. When None, enumerates and
            filters via :func:`list_target_namespaces`.

    Returns a :class:`CorrelationResult` with the flat rows (ready to
    feed ``group_findings.group_rows``) and per-namespace reports for
    coverage classification.
    """
    result = CorrelationResult()
    if namespaces is None:
        namespaces = list_target_namespaces(api)
    for ns in namespaces:
        report = _process_and_emit(api, ns, cve_by_digest, result.flat_rows)
        result.reports.append(report)
    return result
