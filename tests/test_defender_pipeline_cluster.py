"""Unit + integration tests for the P0.6 cluster pipeline.

Covers:

  * Platform-namespace filter (openshift-* / kube-* / default / logging /
    monitoring) — frozen contract in docs/contracts/cli-behavior.md.
  * CVE CSV loader — digest keyed lookup.
  * Owner-reference normalization: ReplicaSet → Deployment,
    ReplicationController-N → DeploymentConfig, empty → Pod fallback.
  * Image digest extraction from ``imageID`` (with/without prefix).
  * Namespace classification: SUCCESS_WITH_PODS / NO_PODS / RBAC_ERR /
    OC_ERR / PARSE_ERR — 403 does NOT abort the scan.
  * End-to-end run_cluster against a mocked ``CoreV1Api`` — writes the
    24-column CSV via ``group_findings.group_rows``.
  * CLI cmd_cluster returns the correct exit codes (0 COMPLETE, 3 PARTIAL).

No live cluster calls. Kubernetes SDK is patched at the client
boundary.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


# ═══════════════════════════════════════════════════════════════════════════
# Helpers to build fake pod / namespace objects (SimpleNamespace tree).
# ═══════════════════════════════════════════════════════════════════════════


def _ns(name: str):
    return SimpleNamespace(metadata=SimpleNamespace(name=name))


def _ns_list(names):
    return SimpleNamespace(items=[_ns(n) for n in names])


def _pod(
    *,
    name: str,
    namespace: str,
    owner_kind: str | None = None,
    owner_name: str | None = None,
    image_ids: list[str] | None = None,
):
    owners = None
    if owner_kind:
        owners = [SimpleNamespace(kind=owner_kind, name=owner_name)]
    return SimpleNamespace(
        metadata=SimpleNamespace(
            name=name,
            namespace=namespace,
            owner_references=owners,
        ),
        status=SimpleNamespace(
            container_statuses=[
                SimpleNamespace(image_id=iid) for iid in (image_ids or [])
            ],
            init_container_statuses=[],
        ),
    )


def _pod_list(pods):
    return SimpleNamespace(items=list(pods))


# ═══════════════════════════════════════════════════════════════════════════
# Platform-namespace filter
# ═══════════════════════════════════════════════════════════════════════════


class TestPlatformNamespaceFilter:
    def test_excludes_openshift_prefix(self) -> None:
        from defender_pipeline.openshift.correlate import _is_platform_namespace
        assert _is_platform_namespace("openshift-monitoring") is True
        assert _is_platform_namespace("openshift") is False   # exact only for literals

    def test_excludes_kube_prefix(self) -> None:
        from defender_pipeline.openshift.correlate import _is_platform_namespace
        assert _is_platform_namespace("kube-system") is True
        assert _is_platform_namespace("kube") is False

    def test_excludes_literal_names(self) -> None:
        from defender_pipeline.openshift.correlate import _is_platform_namespace
        assert _is_platform_namespace("default") is True
        assert _is_platform_namespace("logging") is True
        assert _is_platform_namespace("monitoring") is True

    def test_keeps_user_namespaces(self) -> None:
        from defender_pipeline.openshift.correlate import _is_platform_namespace
        assert _is_platform_namespace("myapp") is False
        assert _is_platform_namespace("payments") is False
        assert _is_platform_namespace("openshift-x-my-team") is True  # still prefix match

    def test_list_target_namespaces_filters(self) -> None:
        from defender_pipeline.openshift.correlate import list_target_namespaces
        api = MagicMock()
        api.list_namespace.return_value = _ns_list([
            "myapp", "openshift-monitoring", "kube-system", "default",
            "payments", "logging",
        ])
        result = list_target_namespaces(api)
        assert result == ["myapp", "payments"]


# ═══════════════════════════════════════════════════════════════════════════
# Owner-reference resolution
# ═══════════════════════════════════════════════════════════════════════════


class TestParentResolution:
    def test_replicaset_normalized_to_deployment(self) -> None:
        from defender_pipeline.openshift.correlate import _resolve_parent
        pod = _pod(name="p", namespace="n",
                   owner_kind="ReplicaSet", owner_name="myapp-abc123")
        assert _resolve_parent(pod) == ("Deployment", "myapp")

    def test_replicationcontroller_normalized_to_deploymentconfig(self) -> None:
        from defender_pipeline.openshift.correlate import _resolve_parent
        pod = _pod(name="p", namespace="n",
                   owner_kind="ReplicationController", owner_name="myapp-42")
        assert _resolve_parent(pod) == ("DeploymentConfig", "myapp")

    def test_replicationcontroller_without_numeric_suffix_kept(self) -> None:
        from defender_pipeline.openshift.correlate import _resolve_parent
        pod = _pod(name="p", namespace="n",
                   owner_kind="ReplicationController", owner_name="myapp")
        assert _resolve_parent(pod) == ("ReplicationController", "myapp")

    def test_no_owner_falls_back_to_pod(self) -> None:
        from defender_pipeline.openshift.correlate import _resolve_parent
        pod = _pod(name="standalone-pod", namespace="n")
        assert _resolve_parent(pod) == ("Pod", "standalone-pod")

    def test_direct_deployment_owner_kept(self) -> None:
        from defender_pipeline.openshift.correlate import _resolve_parent
        pod = _pod(name="p", namespace="n",
                   owner_kind="StatefulSet", owner_name="db-primary")
        assert _resolve_parent(pod) == ("StatefulSet", "db-primary")


# ═══════════════════════════════════════════════════════════════════════════
# Image digest extraction
# ═══════════════════════════════════════════════════════════════════════════


class TestDigestExtraction:
    def test_extracts_sha256_from_docker_pullable(self) -> None:
        from defender_pipeline.openshift.correlate import _extract_image_digests
        pod = _pod(
            name="p", namespace="n",
            image_ids=["docker-pullable://repo/app@sha256:" + "a" * 64],
        )
        digests = _extract_image_digests(pod)
        assert digests == ["sha256:" + "a" * 64]

    def test_extracts_from_bare_sha256(self) -> None:
        from defender_pipeline.openshift.correlate import _extract_image_digests
        pod = _pod(name="p", namespace="n", image_ids=["sha256:" + "b" * 64])
        assert _extract_image_digests(pod) == ["sha256:" + "b" * 64]

    def test_no_digest_returns_empty(self) -> None:
        from defender_pipeline.openshift.correlate import _extract_image_digests
        pod = _pod(name="p", namespace="n", image_ids=["repo/app:latest"])
        assert _extract_image_digests(pod) == []

    def test_multiple_containers_multiple_digests(self) -> None:
        from defender_pipeline.openshift.correlate import _extract_image_digests
        pod = _pod(
            name="p", namespace="n",
            image_ids=[
                "docker-pullable://a@sha256:" + "1" * 64,
                "sha256:" + "2" * 64,
            ],
        )
        assert _extract_image_digests(pod) == [
            "sha256:" + "1" * 64,
            "sha256:" + "2" * 64,
        ]


# ═══════════════════════════════════════════════════════════════════════════
# Namespace classification — the whole 5-state contract
# ═══════════════════════════════════════════════════════════════════════════


def _api_exception(status: int, reason: str = ""):
    """Build a kubernetes ApiException with a specific status code."""
    from kubernetes.client.exceptions import ApiException
    exc = ApiException(status=status, reason=reason)
    return exc


class TestNamespaceClassification:
    def test_success_with_pods(self) -> None:
        from defender_pipeline.openshift.correlate import (
            CoverageState,
            _process_and_emit,
        )
        api = MagicMock()
        api.list_namespaced_pod.return_value = _pod_list([
            _pod(name="p1", namespace="app",
                 owner_kind="ReplicaSet", owner_name="app-abc",
                 image_ids=["sha256:" + "a" * 64]),
        ])
        rows: list = []
        report = _process_and_emit(api, "app", {"sha256:" + "a" * 64: [
            {"repository": "r", "digest": "sha256:" + "a" * 64,
             "cveId": "CVE-1", "severity": "High"},
        ]}, rows)
        assert report.state is CoverageState.SUCCESS_WITH_PODS
        assert report.pod_count == 1
        assert report.match_count == 1
        assert len(rows) == 1
        assert rows[0]["NAMESPACE"] == "app"
        assert rows[0]["PARENT_TYPE"] == "Deployment"
        assert rows[0]["PARENT_NAME"] == "app"

    def test_no_pods(self) -> None:
        from defender_pipeline.openshift.correlate import (
            CoverageState,
            _process_and_emit,
        )
        api = MagicMock()
        api.list_namespaced_pod.return_value = _pod_list([])
        report = _process_and_emit(api, "empty-ns", {}, [])
        assert report.state is CoverageState.NO_PODS

    def test_rbac_err_on_403(self) -> None:
        from defender_pipeline.openshift.correlate import (
            CoverageState,
            _process_and_emit,
        )
        api = MagicMock()
        api.list_namespaced_pod.side_effect = _api_exception(403, "Forbidden")
        report = _process_and_emit(api, "locked-ns", {}, [])
        assert report.state is CoverageState.RBAC_ERR
        assert "403" in report.error_detail

    def test_oc_err_on_500(self) -> None:
        from defender_pipeline.openshift.correlate import (
            CoverageState,
            _process_and_emit,
        )
        api = MagicMock()
        api.list_namespaced_pod.side_effect = _api_exception(500, "Server Error")
        report = _process_and_emit(api, "broken-ns", {}, [])
        assert report.state is CoverageState.OC_ERR

    def test_parse_err_on_generic_exception(self) -> None:
        from defender_pipeline.openshift.correlate import (
            CoverageState,
            _process_and_emit,
        )
        api = MagicMock()
        api.list_namespaced_pod.side_effect = ValueError("bogus response")
        report = _process_and_emit(api, "weird-ns", {}, [])
        assert report.state is CoverageState.PARSE_ERR

    def test_403_on_one_ns_does_not_abort_others(self) -> None:
        """The critical resilience invariant: one namespace's RBAC error
        must NOT abort the whole scan (differs from bash `set -e`)."""
        from defender_pipeline.openshift.correlate import correlate

        api = MagicMock()

        def _side_effect(namespace: str):
            if namespace == "locked":
                raise _api_exception(403)
            return _pod_list([
                _pod(name="ok-pod", namespace=namespace,
                     image_ids=["sha256:" + "a" * 64]),
            ])

        api.list_namespaced_pod.side_effect = _side_effect
        cve_by_digest = {"sha256:" + "a" * 64: [
            {"repository": "r", "digest": "sha256:" + "a" * 64,
             "cveId": "CVE-1", "severity": "High"},
        ]}
        result = correlate(api, cve_by_digest, namespaces=["ok", "locked", "other"])

        assert len(result.reports) == 3
        assert result.reports[0].state.value == "SUCCESS_WITH_PODS"
        assert result.reports[1].state.value == "RBAC_ERR"
        assert result.reports[2].state.value == "SUCCESS_WITH_PODS"
        # The 2 non-locked namespaces contributed rows.
        assert len(result.flat_rows) == 2


# ═══════════════════════════════════════════════════════════════════════════
# CVE CSV loader
# ═══════════════════════════════════════════════════════════════════════════


class TestLoadCveCsvByDigest:
    def test_indexes_by_digest(self, tmp_path: Path) -> None:
        from defender_pipeline.openshift.correlate import load_cve_csv_by_digest
        csv_path = tmp_path / "vuln.csv"
        csv_path.write_text(
            '"repository","digest","tag","cvssScore","cveId","severity","packageName"\n'
            '"r1","sha256:aaa","v1","9.8","CVE-1","Critical","openssl"\n'
            '"r1","sha256:aaa","v1","8.1","CVE-2","High","openssl"\n'
            '"r2","sha256:bbb","v1","7.5","CVE-3","High","curl"\n',
            encoding="utf-8",
        )
        by_digest = load_cve_csv_by_digest(csv_path)
        assert set(by_digest.keys()) == {"sha256:aaa", "sha256:bbb"}
        assert len(by_digest["sha256:aaa"]) == 2
        assert len(by_digest["sha256:bbb"]) == 1


# ═══════════════════════════════════════════════════════════════════════════
# End-to-end: run_cluster with mocked CoreV1Api → writes 24-col CSV
# ═══════════════════════════════════════════════════════════════════════════


@pytest.fixture
def cve_csv(tmp_path: Path) -> Path:
    """Fixture with one CVE row keyed by a known digest."""
    p = tmp_path / "vuln.csv"
    p.write_text(
        '"repository","digest","tag","cvssScore","cveId","severity",'
        '"packageCategory","packageLanguage","packageName","currentVersion",'
        '"fixedVersion","patchable","remediation","fixStatus","cveAgeDays",'
        '"isInExploitKit","hasPublishedExploit","hasVerifiedExploit","lastPushedToRegistryUTC"\n'
        '"myrepo","sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","v1.0","9.8","CVE-2024-1","Critical",'
        '"OS","","openssl","1.0","2.0","true","upgrade","FixAvailable","100",'
        '"true","true","true","2024-01-01"\n',
        encoding="utf-8",
    )
    return p


class TestRunClusterEndToEnd:
    def test_writes_24_column_csv(self, tmp_path: Path, cve_csv: Path) -> None:
        from defender_pipeline.openshift.cluster import (
            ClusterOptions,
            run_cluster,
        )
        from defender_pipeline.openshift.csv_contracts import (
            RESULTADO_CRUZAMENTO_HEADER_COLUMNS,
        )

        mock_api = MagicMock()
        mock_api.list_namespace.return_value = _ns_list(["app-ns"])
        mock_api.list_namespaced_pod.return_value = _pod_list([
            _pod(
                name="myapp-pod-1", namespace="app-ns",
                owner_kind="ReplicaSet", owner_name="myapp-abc",
                image_ids=["docker-pullable://myrepo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            ),
        ])

        output = tmp_path / "cruzamento.csv"
        with patch("defender_pipeline.openshift.cluster.get_core_api",
                   return_value=mock_api), \
             patch("defender_pipeline.openshift.cluster.log"):
            exit_code = run_cluster(ClusterOptions(
                vulnerabilities=cve_csv, output=output,
            ))
        assert exit_code == 0  # COMPLETE — no errors

        # 24-column CSV emitted
        with output.open("r", encoding="utf-8") as f:
            rows = list(csv.reader(f))
        assert rows[0] == RESULTADO_CRUZAMENTO_HEADER_COLUMNS
        # 1 data row (1 pod × 1 digest × 1 CVE → aggregated to 1 group)
        assert len(rows) == 2
        assert rows[1][0] == "app-ns"
        assert rows[1][1] == "Deployment"
        assert rows[1][2] == "myapp"
        assert rows[1][4] == "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    def test_partial_coverage_exits_3(self, tmp_path: Path, cve_csv: Path) -> None:
        from defender_pipeline.openshift.cluster import (
            ClusterOptions,
            run_cluster,
        )

        mock_api = MagicMock()
        mock_api.list_namespace.return_value = _ns_list(["ok-ns", "locked-ns"])

        def _side_effect(namespace: str):
            if namespace == "locked-ns":
                raise _api_exception(403)
            return _pod_list([])

        mock_api.list_namespaced_pod.side_effect = _side_effect

        output = tmp_path / "cruzamento.csv"
        with patch("defender_pipeline.openshift.cluster.get_core_api",
                   return_value=mock_api):
            exit_code = run_cluster(ClusterOptions(
                vulnerabilities=cve_csv, output=output,
            ))
        assert exit_code == 3  # PARTIAL — one RBAC error

    def test_missing_vulnerabilities_csv_returns_1(self, tmp_path: Path) -> None:
        from defender_pipeline.openshift.cluster import (
            ClusterOptions,
            run_cluster,
        )
        exit_code = run_cluster(ClusterOptions(
            vulnerabilities=tmp_path / "nope.csv",
            output=tmp_path / "out.csv",
        ))
        assert exit_code == 1


# ═══════════════════════════════════════════════════════════════════════════
# Deterministic output ordering
# ═══════════════════════════════════════════════════════════════════════════


class TestOutputOrdering:
    """Cluster CSV must come out sorted by
    NAMESPACE → PARENT_TYPE → PARENT_NAME → REPOSITORY → DIGEST.
    Kubernetes list order isn't stable across API calls, so downstream
    tools/diff/tests need a deterministic write order."""

    def _multi_cve_csv(self, tmp_path: Path) -> Path:
        p = tmp_path / "multi.csv"
        # 3 digests, keyed by short sha256 (padded to 64 hex)
        p.write_text(
            '"repository","digest","tag","cvssScore","cveId","severity",'
            '"packageCategory","packageLanguage","packageName","currentVersion",'
            '"fixedVersion","patchable","remediation","fixStatus","cveAgeDays",'
            '"isInExploitKit","hasPublishedExploit","hasVerifiedExploit","lastPushedToRegistryUTC"\n'
            + "".join(
                f'"{repo}","sha256:{d}","v1","9.8","CVE-2024-{i}","Critical",'
                '"OS","","openssl","1.0","2.0","true","up","FixAvailable","10",'
                '"true","true","true","2024-01-01"\n'
                for i, (repo, d) in enumerate([
                    ("repo-z", "c" * 64),
                    ("repo-a", "a" * 64),
                    ("repo-m", "b" * 64),
                ], start=1)
            ),
            encoding="utf-8",
        )
        return p

    def test_rows_sorted_by_ns_parent_repo_digest(self, tmp_path: Path) -> None:
        from defender_pipeline.openshift.cluster import (
            ClusterOptions,
            run_cluster,
        )

        cve_csv = self._multi_cve_csv(tmp_path)

        # Kubernetes returns namespaces + pods in unpredictable order.
        # Feed them scrambled so the test can't accidentally pass on
        # insertion order.
        mock_api = MagicMock()
        mock_api.list_namespace.return_value = _ns_list([
            "z-ns", "a-ns", "m-ns",
        ])

        def _pods_for(namespace: str, **_kw):
            if namespace == "z-ns":
                return _pod_list([
                    _pod(name="p-z", namespace=namespace,
                         owner_kind="ReplicaSet", owner_name="app-z-abc",
                         image_ids=[f"docker-pullable://repo-z@sha256:{'c'*64}"]),
                ])
            if namespace == "a-ns":
                return _pod_list([
                    _pod(name="p-a", namespace=namespace,
                         owner_kind="ReplicaSet", owner_name="app-a-abc",
                         image_ids=[f"docker-pullable://repo-a@sha256:{'a'*64}"]),
                ])
            if namespace == "m-ns":
                return _pod_list([
                    _pod(name="p-m", namespace=namespace,
                         owner_kind="ReplicaSet", owner_name="app-m-abc",
                         image_ids=[f"docker-pullable://repo-m@sha256:{'b'*64}"]),
                ])
            return _pod_list([])

        mock_api.list_namespaced_pod.side_effect = _pods_for

        output = tmp_path / "sorted.csv"
        with patch("defender_pipeline.openshift.cluster.get_core_api",
                   return_value=mock_api), \
             patch("defender_pipeline.openshift.cluster.log"):
            run_cluster(ClusterOptions(vulnerabilities=cve_csv, output=output))

        with output.open("r", encoding="utf-8") as f:
            rows = list(csv.reader(f))
        # rows[0] = header; data starts at rows[1]
        namespaces = [r[0] for r in rows[1:]]
        assert namespaces == ["a-ns", "m-ns", "z-ns"], (
            f"expected NS asc, got {namespaces}"
        )

    def test_output_stable_across_calls(self, tmp_path: Path) -> None:
        """Same input twice must produce byte-identical CSV."""
        from defender_pipeline.openshift.cluster import (
            ClusterOptions,
            run_cluster,
        )

        cve_csv = self._multi_cve_csv(tmp_path)
        mock_api = MagicMock()
        mock_api.list_namespace.return_value = _ns_list(["a-ns", "b-ns"])
        mock_api.list_namespaced_pod.return_value = _pod_list([
            _pod(name="p", namespace="a-ns",
                 owner_kind="ReplicaSet", owner_name="app-abc",
                 image_ids=[f"docker-pullable://repo-a@sha256:{'a'*64}"]),
        ])

        out1 = tmp_path / "run1.csv"
        out2 = tmp_path / "run2.csv"
        for out in (out1, out2):
            with patch("defender_pipeline.openshift.cluster.get_core_api",
                       return_value=mock_api), \
                 patch("defender_pipeline.openshift.cluster.log"):
                run_cluster(ClusterOptions(vulnerabilities=cve_csv, output=out))

        assert out1.read_bytes() == out2.read_bytes()


# ═══════════════════════════════════════════════════════════════════════════
# CLI cmd_cluster
# ═══════════════════════════════════════════════════════════════════════════


class TestCliCluster:
    def test_invokes_run_cluster_and_returns_its_exit_code(self) -> None:
        from defender_pipeline import cli
        args = MagicMock()
        args.vulnerabilities = "in.csv"
        args.output = "out.csv"
        args.kubeconfig = None
        args.log_format = "text"
        args.log_level = "INFO"

        with patch("defender_pipeline.openshift.cluster.run_cluster",
                   return_value=3) as mock_run, \
             patch("defender_pipeline.logging_setup.setup"):
            rc = cli.cmd_cluster(args)
        assert rc == 3
        mock_run.assert_called_once()

    def test_returns_error_on_exception(self) -> None:
        from defender_pipeline import cli
        args = MagicMock()
        args.vulnerabilities = "in.csv"
        args.output = "out.csv"
        args.kubeconfig = None
        args.log_format = "text"
        args.log_level = "INFO"

        with patch("defender_pipeline.openshift.cluster.run_cluster",
                   side_effect=RuntimeError("boom")), \
             patch("defender_pipeline.logging_setup.setup"):
            rc = cli.cmd_cluster(args)
        assert rc == cli.EXIT_ERROR
