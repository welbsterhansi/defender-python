"""Unit + integration tests for the P0.5 scan pipeline.

Covers:

  * KQL builders (pure functions — output stability).
  * Batch-split-on-failure orchestrator (utils.batching).
  * Models — from_arg_row parsing tolerance.
  * Enrich — merge semantics, filter, distinct dedup, fallback ladder.
  * Scan orchestrator — full pipeline against a mocked ARG client.
  * CLI scan subcommand — with mocked scan.run_scan.
  * Diff subcommand — identical / differing.

No live Azure calls. Azure SDK classes are patched at the client
boundary so tests run without ``.[pipeline]`` extras installed.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


# ═══════════════════════════════════════════════════════════════════════════
# KQL builders
# ═══════════════════════════════════════════════════════════════════════════


class TestKqlBuilders:
    def test_enumerate_query_contains_distinct(self) -> None:
        from defender_pipeline.azure.queries import build_enumerate_digests_query
        kql = build_enumerate_digests_query("")
        assert 'type == "microsoft.security/assessments"' in kql
        assert "distinct _repository, _digest" in kql

    def test_enumerate_query_injects_filter(self) -> None:
        from defender_pipeline.azure.queries import build_enumerate_digests_query
        kql = build_enumerate_digests_query('| where properties.foo == "bar"')
        assert '| where properties.foo == "bar"' in kql

    def test_batched_assessments_query_uses_in_clause(self) -> None:
        from defender_pipeline.azure.queries import build_batched_assessments_query
        kql = build_batched_assessments_query(["sha256:aaa", "sha256:bbb"])
        assert '_digest in ("sha256:aaa", "sha256:bbb")' in kql
        assert "inlineSeverity" in kql
        assert "mv-expand cve = _cves" in kql

    def test_batched_cvedetails_query_uppercases_join_key(self) -> None:
        from defender_pipeline.azure.queries import build_batched_cvedetails_query
        kql = build_batched_cvedetails_query(["CVE-2024-1", "CVE-2024-2"])
        assert 'toupper(coalesce(tostring(properties.cveId), tostring(name)))' in kql
        assert 'cveIdJoin in ("CVE-2024-1", "CVE-2024-2")' in kql

    def test_batched_cvedetails_query_has_no_cvss_31(self) -> None:
        """Guardrail — schema doesn't have "3.1" key (see erros.md)."""
        from defender_pipeline.azure.queries import build_batched_cvedetails_query
        kql = build_batched_cvedetails_query(["CVE-1"])
        assert 'cvss["3.1"]' not in kql

    def test_kql_string_list_rejects_injection(self) -> None:
        """Defensive: values with " or \\ get dropped."""
        from defender_pipeline.azure.queries import _kql_string_list
        assert _kql_string_list(["ok", 'bad"item', "also-ok"]) == '"ok", "also-ok"'

    def test_scope_filter_scan_image_wins(self) -> None:
        from defender_pipeline.azure.queries import build_scope_filter
        result = build_scope_filter(
            repository="ignored",
            scan_repository="app",
            scan_digest="sha256:abc",
        )
        assert 'contains "app"' in result
        assert 'contains "abc"' in result

    def test_scope_filter_repositories_anchored(self) -> None:
        from defender_pipeline.azure.queries import build_scope_filter
        result = build_scope_filter(repositories=["app-backend", "team/svc"])
        assert 'contains "repositories-app-backend-images-"' in result
        assert 'contains "repositories-team-svc-images-"' in result
        assert " or " in result

    def test_scope_filter_empty_when_no_args(self) -> None:
        from defender_pipeline.azure.queries import build_scope_filter
        assert build_scope_filter() == ""

    # ─── ISSUE-002 P0.1 — total-order `order by` after distinct ──────────
    # Without a total ordering ARG skip-token pagination may duplicate or
    # omit rows across pages (Microsoft docs). The order-by key must make
    # rows unique.

    def test_enumerate_query_has_total_order_by(self) -> None:
        from defender_pipeline.azure.queries import build_enumerate_digests_query
        kql = build_enumerate_digests_query("")
        # Must appear AFTER distinct, otherwise ordering happens before
        # dedup and doesn't help page stability.
        distinct_idx = kql.index("distinct _repository, _digest")
        order_idx = kql.index("| order by")
        assert order_idx > distinct_idx, (
            "`order by` must come after `distinct` so dedup happens first"
        )
        # Key = (_repository, _digest) is already the distinct tuple,
        # so ordering on both gives a total order over emitted rows.
        assert "_repository" in kql[order_idx:order_idx + 200]
        assert "_digest" in kql[order_idx:order_idx + 200]

    def test_batched_assessments_query_has_total_order_by(self) -> None:
        from defender_pipeline.azure.queries import build_batched_assessments_query
        kql = build_batched_assessments_query(["sha256:aaa"])
        distinct_idx = kql.index("| distinct")
        order_idx = kql.index("| order by")
        assert order_idx > distinct_idx, (
            "`order by` must come after `distinct`"
        )
        # Identity tuple for an assessment row = (repository, digest, cveId,
        # packageName). Ordering by these makes the per-page cursor stable
        # even if the service reorders rows that differ only on attributes.
        tail = kql[order_idx:]
        for key in ("repository", "digest", "cveId", "packageName"):
            assert key in tail, f"order by must include {key}"

    def test_batched_cvedetails_query_has_total_order_by(self) -> None:
        from defender_pipeline.azure.queries import build_batched_cvedetails_query
        kql = build_batched_cvedetails_query(["CVE-2024-1"])
        # cvedetails ends with `project` after `summarize by cveIdJoin`,
        # so cveIdJoin is already unique per emitted row.
        summarize_idx = kql.index("summarize")
        order_idx = kql.index("| order by")
        assert order_idx > summarize_idx, (
            "`order by` must come after `summarize ... by cveIdJoin`"
        )
        assert "cveIdJoin" in kql[order_idx:order_idx + 200]


# ═══════════════════════════════════════════════════════════════════════════
# Batching (split-on-failure)
# ═══════════════════════════════════════════════════════════════════════════


class TestBatchSplit:
    def test_success_path_no_split(self) -> None:
        from defender_pipeline.utils.batching import run_batched_with_split
        calls: list[list[int]] = []

        def run_batch(chunk):
            calls.append(list(chunk))
            return [i * 10 for i in chunk]

        result = run_batched_with_split(
            [1, 2, 3, 4, 5], run_batch, initial_batch_size=2,
        )
        assert result == [10, 20, 30, 40, 50]
        assert calls == [[1, 2], [3, 4], [5]]

    def test_split_on_too_complex(self) -> None:
        from defender_pipeline.utils.batching import (
            BatchTooComplex,
            run_batched_with_split,
        )
        call_sizes: list[int] = []

        def run_batch(chunk):
            call_sizes.append(len(chunk))
            if len(chunk) > 2:
                raise BatchTooComplex("mock")
            return [i for i in chunk]

        result = run_batched_with_split(
            [1, 2, 3, 4], run_batch, initial_batch_size=4,
        )
        assert result == [1, 2, 3, 4]
        # First call: size 4 → BatchTooComplex → splits to 2 + 2.
        assert 4 in call_sizes
        assert call_sizes.count(2) == 2

    def test_single_item_failure_raises_exhausted(self) -> None:
        from defender_pipeline.utils.batching import (
            BatchExhausted,
            BatchTooComplex,
            run_batched_with_split,
        )

        def run_batch(chunk):
            raise BatchTooComplex("always")

        with pytest.raises(BatchExhausted):
            run_batched_with_split([1], run_batch, initial_batch_size=1)


# ═══════════════════════════════════════════════════════════════════════════
# Models — from_arg_row
# ═══════════════════════════════════════════════════════════════════════════


class TestAssessmentRowParsing:
    def test_all_fields_present(self) -> None:
        from defender_pipeline.findings.models import AssessmentRow
        row = AssessmentRow.from_arg_row({
            "repository": "myrepo",
            "digest": "sha256:aaa",
            "cveId": "CVE-2024-1",
            "packageName": "openssl",
            "currentVersion": "1.0",
            "fixedVersion": "2.0",
            "fixStatus": "FixAvailable",
            "packageCategory": "OS",
            "packageLanguage": "",
            "remediation": "Update, please",
            "lastPushedToRegistryUTC": "2024-01-01",
            "inlineSeverity": "High",
            "inlineCvssBase": 8.1,
            "inlinePublishedDate": "2023-01-01T00:00:00Z",
            "inlineInExploitKit": "true",
            "inlinePubliclyDisclosed": "false",
            "inlineVerified": "true",
        })
        assert row.repository == "myrepo"
        assert row.inline_cvss_base == 8.1
        assert row.remediation == "Update, please"

    def test_missing_fields_default_to_empty(self) -> None:
        from defender_pipeline.findings.models import AssessmentRow
        row = AssessmentRow.from_arg_row({
            "repository": "r",
            "digest": "d",
            "cveId": "CVE-1",
            "packageName": "p",
            "currentVersion": "",
            "fixedVersion": "",
            "fixStatus": "",
            "packageCategory": "",
            "packageLanguage": "",
            "remediation": "",
            "lastPushedToRegistryUTC": "",
        })
        assert row.inline_cvss_base == 0.0
        assert row.inline_severity == ""


class TestEnrichmentRowParsing:
    def test_uppercases_cveid_join(self) -> None:
        from defender_pipeline.findings.models import EnrichmentRow
        row = EnrichmentRow.from_arg_row({
            "cveIdJoin": "cve-2024-lowercase",
            "cvssEnrich": 9.8,
            "publishedDateEnrich": "2024-01-01",
            "severityEnrich": "Critical",
            "verifiedExpEnrich": 1,
            "publishedExpEnrich": 1,
            "inExploitKitEnrich": 0,
        })
        assert row.cve_id_join == "CVE-2024-LOWERCASE"
        assert row.cvss == 9.8

    def test_none_cvss_stays_none(self) -> None:
        from defender_pipeline.findings.models import EnrichmentRow
        row = EnrichmentRow.from_arg_row({
            "cveIdJoin": "CVE-1", "cvssEnrich": None,
            "publishedDateEnrich": "", "severityEnrich": "",
            "verifiedExpEnrich": 0, "publishedExpEnrich": 0,
            "inExploitKitEnrich": 0,
        })
        assert row.cvss is None


# ═══════════════════════════════════════════════════════════════════════════
# Enrich merger
# ═══════════════════════════════════════════════════════════════════════════


def _mk_assessment(**kwargs):
    from defender_pipeline.findings.models import AssessmentRow
    defaults = dict(
        repository="repo", digest="sha256:aaa", cve_id="CVE-2024-1",
        package_name="openssl", current_version="1.0", fixed_version="2.0",
        fix_status="FixAvailable", package_category="OS",
        package_language="", remediation="upgrade",
        last_pushed_to_registry_utc="2024-01-01",
    )
    defaults.update(kwargs)
    return AssessmentRow(**defaults)


def _mk_enrichment(**kwargs):
    from defender_pipeline.findings.models import EnrichmentRow
    defaults = dict(
        cve_id_join="CVE-2024-1", cvss=9.8,
        published_date="2024-05-01T00:00:00Z", severity="Critical",
        verified=1, publicly_disclosed=1, in_exploit_kit=1,
    )
    defaults.update(kwargs)
    return EnrichmentRow(**defaults)


class TestEnrichMerge:
    def test_enrichment_wins_over_inline(self) -> None:
        from defender_pipeline.findings.enrich import merge
        assessment = _mk_assessment(
            inline_severity="High", inline_cvss_base=8.1,
        )
        enrichment = {"CVE-2024-1": _mk_enrichment(cvss=9.8, severity="Critical")}
        findings = merge([assessment], enrichment, {}, min_score=0, max_score=10)
        assert len(findings) == 1
        assert findings[0].cvss_score == "9.8"
        assert findings[0].severity == "Critical"

    def test_inline_fallback_when_no_enrichment(self) -> None:
        from defender_pipeline.findings.enrich import merge
        assessment = _mk_assessment(
            cve_id="CVE-9999-NOENRICH",
            inline_severity="High", inline_cvss_base=8.1,
        )
        findings = merge([assessment], {}, {}, min_score=0, max_score=10)
        assert findings[0].cvss_score == "8.1"
        assert findings[0].severity == "High"

    def test_exploit_flags_or_between_enrichment_and_inline(self) -> None:
        """Regression guard — see erros.md.

        When ARG runs with the SDK's enlatado api-version (2021-03-01),
        ``microsoft.security/cvedetails`` may omit
        ``exploitabilityDetails``. The KQL enrichment then emits
        ``false`` for all three exploit chips via ``iff(isnull, false,
        ...)``. Before the fix, enrichment overrode inline so the real
        positives from the assessment row disappeared from the CSV.
        After the fix, we OR the two sources — any positive wins.
        """
        from defender_pipeline.findings.enrich import merge
        assessment = _mk_assessment(
            inline_severity="High", inline_cvss_base=8.1,
            inline_in_exploit_kit="true",
            inline_publicly_disclosed="true",
            inline_verified="true",
        )
        # Enrichment present but exploit flags all zero (older-API shape).
        enrichment = {"CVE-2024-1": _mk_enrichment(
            cvss=9.8, severity="Critical",
            verified=0, publicly_disclosed=0, in_exploit_kit=0,
        )}
        findings = merge([assessment], enrichment, {}, min_score=0, max_score=10)
        assert len(findings) == 1
        assert findings[0].is_in_exploit_kit == "true"
        assert findings[0].has_published_exploit == "true"
        assert findings[0].has_verified_exploit == "true"
        # CVSS/severity still follow enrichment-wins policy.
        assert findings[0].cvss_score == "9.8"
        assert findings[0].severity == "Critical"

    def test_exploit_flags_both_false_stay_false(self) -> None:
        """If neither source reports an exploit, the chip is 'false'."""
        from defender_pipeline.findings.enrich import merge
        assessment = _mk_assessment()  # all inline exploit fields empty
        enrichment = {"CVE-2024-1": _mk_enrichment(
            verified=0, publicly_disclosed=0, in_exploit_kit=0,
        )}
        findings = merge([assessment], enrichment, {}, min_score=0, max_score=10)
        assert findings[0].is_in_exploit_kit == "false"
        assert findings[0].has_published_exploit == "false"
        assert findings[0].has_verified_exploit == "false"

    def test_min_score_filter_drops_row(self) -> None:
        from defender_pipeline.findings.enrich import merge
        assessment = _mk_assessment(inline_severity="Low")  # cvss ~= 0.1
        findings = merge([assessment], {}, {}, min_score=5.0, max_score=10.0)
        assert findings == []

    def test_distinct_dedup(self) -> None:
        from defender_pipeline.findings.enrich import merge
        a = _mk_assessment()
        findings = merge([a, a], {}, {}, min_score=0, max_score=10)
        assert len(findings) == 1

    def test_tag_fallback_to_na(self) -> None:
        from defender_pipeline.findings.enrich import merge
        a = _mk_assessment()
        findings = merge([a], {"CVE-2024-1": _mk_enrichment()}, {},
                         min_score=0, max_score=10)
        assert findings[0].tag == "N/A"

    def test_tag_from_cache(self) -> None:
        from defender_pipeline.findings.enrich import merge
        a = _mk_assessment()
        cache = {"repo@sha256:aaa": "v1.0"}
        findings = merge([a], {"CVE-2024-1": _mk_enrichment()}, cache,
                         min_score=0, max_score=10)
        assert findings[0].tag == "v1.0"

    def test_non_cve_prefix_skipped(self) -> None:
        from defender_pipeline.findings.enrich import merge
        rows = [_mk_assessment(cve_id="NOT-A-CVE"), _mk_assessment()]
        findings = merge(rows, {}, {}, min_score=0, max_score=10)
        assert len(findings) == 1
        assert findings[0].cve_id == "CVE-2024-1"

    def test_deterministic_sort_order(self) -> None:
        """CSV must come out sorted by cvssScore desc, then repository asc,
        digest asc, cveId asc, packageName asc — replaces the KQL
        ``order by`` we lost after the JOIN split. Diff/tests/downstream
        depend on this being stable across runs."""
        from defender_pipeline.findings.enrich import merge

        # Deliberately provide input in reversed/scrambled order so the
        # test would trivially pass if sort were absent AND happened to
        # match insertion order. Different repos, digests, cvss.
        rows = [
            _mk_assessment(  # low cvss, later repo — should end up LAST
                repository="zzz", digest="sha256:zzz",
                cve_id="CVE-2024-99", package_name="pkg-z",
                inline_severity="Low", inline_cvss_base=3.0,
            ),
            _mk_assessment(  # highest cvss — should be FIRST
                repository="aaa", digest="sha256:aaa",
                cve_id="CVE-2024-01", package_name="pkg-a",
                inline_severity="Critical", inline_cvss_base=9.9,
            ),
            _mk_assessment(  # same cvss as first — repo asc tiebreak
                repository="bbb", digest="sha256:bbb",
                cve_id="CVE-2024-05", package_name="pkg-b",
                inline_severity="Critical", inline_cvss_base=9.9,
            ),
            _mk_assessment(  # medium cvss — middle
                repository="mmm", digest="sha256:mmm",
                cve_id="CVE-2024-50", package_name="pkg-m",
                inline_severity="High", inline_cvss_base=7.5,
            ),
        ]
        findings = merge(rows, {}, {}, min_score=0, max_score=10)
        cvss_order = [f.cvss_score for f in findings]
        repo_order = [f.repository for f in findings]
        assert cvss_order == ["9.9", "9.9", "7.5", "3"]
        # Within tied cvss=9.9, repo asc breaks tie → aaa before bbb
        assert repo_order[0] == "aaa"
        assert repo_order[1] == "bbb"
        assert repo_order[3] == "zzz"

    def test_sort_is_stable_across_calls(self) -> None:
        """Same input must produce byte-identical output every time —
        no dict / set iteration order leaking through."""
        from defender_pipeline.findings.enrich import merge
        rows = [
            _mk_assessment(repository="r2", digest="sha256:222",
                           cve_id="CVE-2024-B", inline_cvss_base=8.0),
            _mk_assessment(repository="r1", digest="sha256:111",
                           cve_id="CVE-2024-A", inline_cvss_base=8.0),
        ]
        out1 = merge(rows, {}, {}, min_score=0, max_score=10)
        out2 = merge(rows, {}, {}, min_score=0, max_score=10)
        assert [f.repository for f in out1] == [f.repository for f in out2]
        assert [f.repository for f in out1] == ["r1", "r2"]


# ═══════════════════════════════════════════════════════════════════════════
# Scan orchestrator — full pipeline with mocked ARG client
# ═══════════════════════════════════════════════════════════════════════════


class _MockArgClient:
    """In-memory ARG client that answers by KQL substring match."""

    def __init__(self, enum_data, assess_data, cvedetails_data):
        self.enum_data = enum_data
        self.assess_data = assess_data
        self.cvedetails_data = cvedetails_data
        self.calls = 0

    def iter_pages(self, query, top=1000):
        self.calls += 1
        if "distinct _repository, _digest" in query:
            yield self.enum_data
        elif "inlineSeverity" in query:
            yield self.assess_data
        elif "cvssEnrich" in query:
            yield self.cvedetails_data
        else:
            yield []


class TestScanOrchestrator:
    def test_full_pipeline_end_to_end(self, tmp_path: Path) -> None:
        from defender_pipeline.findings.scan import ScanOptions, run_scan

        arg = _MockArgClient(
            enum_data=[{"_repository": "myrepo", "_digest": "sha256:aaa"}],
            assess_data=[{
                "repository": "myrepo", "digest": "sha256:aaa",
                "cveId": "CVE-2024-1", "packageName": "openssl",
                "currentVersion": "1.0", "fixedVersion": "2.0",
                "fixStatus": "FixAvailable", "packageCategory": "OS",
                "packageLanguage": "", "remediation": "Update, please",
                "lastPushedToRegistryUTC": "2024-01-01",
                "inlineSeverity": "", "inlineCvssBase": 0,
                "inlinePublishedDate": "", "inlineInExploitKit": "",
                "inlinePubliclyDisclosed": "", "inlineVerified": "",
            }],
            cvedetails_data=[{
                "cveIdJoin": "CVE-2024-1", "cvssEnrich": 9.8,
                "publishedDateEnrich": "2024-05-01T00:00:00Z",
                "severityEnrich": "Critical",
                "verifiedExpEnrich": 1, "publishedExpEnrich": 1,
                "inExploitKitEnrich": 1,
            }],
        )
        out = tmp_path / "vuln.csv"
        rows = run_scan(
            ScanOptions(
                acr_name="mock-acr", min_score=0, max_score=10,
                skip_tags=True, output=out,
            ),
            arg_client=arg,
        )
        assert rows == 1
        content = out.read_text(encoding="utf-8")
        lines = content.splitlines()
        assert len(lines) == 2  # header + 1 row
        # Header exact match
        assert lines[0].startswith('"repository","digest","tag","cvssScore"')
        # Row starts with our data
        assert lines[1].startswith('"myrepo","sha256:aaa","N/A","9.8","CVE-2024-1","Critical"')
        # 19 fields = 38 double quotes
        assert lines[1].count('"') == 38

    def test_empty_enumerate_produces_header_only_csv(self, tmp_path: Path) -> None:
        from defender_pipeline.findings.scan import ScanOptions, run_scan
        arg = _MockArgClient(enum_data=[], assess_data=[], cvedetails_data=[])
        out = tmp_path / "empty.csv"
        rows = run_scan(
            ScanOptions(acr_name="x", skip_tags=True, output=out),
            arg_client=arg,
        )
        assert rows == 0
        lines = out.read_text().splitlines()
        assert len(lines) == 1  # header only


# ═══════════════════════════════════════════════════════════════════════════
# ResourceGraphClient — SDK plumbing (api-version)
# ═══════════════════════════════════════════════════════════════════════════


class TestResourceGraphClientApiVersion:
    """Guards against the regression where ``Config.arg_api_version`` was
    defined but never forwarded to the SDK — leaving the pipeline on the
    SDK default (2021-03-01), under which ``microsoft.security/cvedetails``
    omits ``exploitabilityDetails`` and exploit flags silently zero out."""

    def test_default_config_pins_api_version_2022_10_01(self) -> None:
        from defender_pipeline.azure.resource_graph import ResourceGraphClient

        with patch("azure.mgmt.resourcegraph.ResourceGraphClient") as sdk_mock:
            ResourceGraphClient(credential=MagicMock())

        sdk_mock.assert_called_once()
        _, kwargs = sdk_mock.call_args
        assert kwargs.get("api_version") == "2022-10-01"

    def test_explicit_config_is_forwarded(self) -> None:
        from defender_pipeline.azure.resource_graph import ResourceGraphClient
        from defender_pipeline.config import Config

        with patch("azure.mgmt.resourcegraph.ResourceGraphClient") as sdk_mock:
            ResourceGraphClient(
                credential=MagicMock(), config=Config(),
            )

        _, kwargs = sdk_mock.call_args
        assert kwargs.get("api_version") == "2022-10-01"

    def test_custom_api_version_overrides_default(self) -> None:
        """Operators can override via Config without editing the client."""
        from defender_pipeline.azure.resource_graph import ResourceGraphClient
        from defender_pipeline.config import Config

        custom = Config(arg_api_version="2024-04-01")
        with patch("azure.mgmt.resourcegraph.ResourceGraphClient") as sdk_mock:
            ResourceGraphClient(credential=MagicMock(), config=custom)

        _, kwargs = sdk_mock.call_args
        assert kwargs.get("api_version") == "2024-04-01"


# ═══════════════════════════════════════════════════════════════════════════
# _translate_arg_error — ARG exception hardening
# ═══════════════════════════════════════════════════════════════════════════


class TestTranslateArgError:
    """Guard against regressions in the substring-free detection of
    ``UnexpectedQueryExecutionError``. If the SDK wraps the message
    differently (localization, versioning), ``_translate_arg_error``
    must still catch the structured code path and raise BatchTooComplex
    — otherwise too-complex batches stop splitting and runs fail."""

    def _fake_exc(self, *, status_code=400, code=None, details=None, message=""):
        """Build a minimal Azure-SDK-shaped exception. Plain classes
        (not MagicMock) so ``__str__`` and attribute shape are honest."""
        class _Error:
            pass

        class _Exc(Exception):
            def __init__(self):
                super().__init__(message)
            def __str__(self):
                return message

        exc = _Exc()
        exc.status_code = status_code
        if code is not None or details is not None:
            err = _Error()
            err.code = code
            err.details = details or []
            exc.error = err
        else:
            exc.error = None
        return exc

    def _detail(self, code: str):
        """ODataV4Format-shaped detail (has .code attribute)."""
        class _D:
            pass
        d = _D()
        d.code = code
        return d

    def test_detects_too_complex_in_top_level_code(self) -> None:
        from defender_pipeline.azure.resource_graph import (
            BatchTooComplex,
            _translate_arg_error,
        )
        exc = self._fake_exc(code="UnexpectedQueryExecutionError")
        with pytest.raises(BatchTooComplex):
            _translate_arg_error(exc)

    def test_detects_too_complex_in_nested_details(self) -> None:
        """ARG actually returns code='InternalServerError' at the top
        and the real code inside details — this is the common path."""
        from defender_pipeline.azure.resource_graph import (
            BatchTooComplex,
            _translate_arg_error,
        )
        exc = self._fake_exc(
            code="InternalServerError",
            details=[self._detail("UnexpectedQueryExecutionError")],
            message="opaque",
        )
        with pytest.raises(BatchTooComplex):
            _translate_arg_error(exc)

    def test_detects_too_complex_in_dict_shaped_details(self) -> None:
        """Some SDK paths leave details as plain dicts, not ODataV4Format."""
        from defender_pipeline.azure.resource_graph import (
            BatchTooComplex,
            _translate_arg_error,
        )
        exc = self._fake_exc(
            code="InternalServerError",
            details=[{"code": "UnexpectedQueryExecutionError"}],
            message="opaque",
        )
        with pytest.raises(BatchTooComplex):
            _translate_arg_error(exc)

    def test_substring_fallback_for_rewrapped_errors(self) -> None:
        """If the SDK ever drops the structured .error payload, we
        still detect via substring on str(exc)."""
        from defender_pipeline.azure.resource_graph import (
            BatchTooComplex,
            _translate_arg_error,
        )
        exc = self._fake_exc(
            message="(InternalServerError) UnexpectedQueryExecutionError",
        )
        with pytest.raises(BatchTooComplex):
            _translate_arg_error(exc)

    def test_transient_mapping_still_works(self) -> None:
        from defender_pipeline.azure.resource_graph import _translate_arg_error
        from defender_pipeline.utils.retry import TransientARGError
        exc = self._fake_exc(status_code=503, message="service unavailable")
        with pytest.raises(TransientARGError):
            _translate_arg_error(exc)

    def test_terminal_errors_propagate(self) -> None:
        """4xx that isn't too-complex and isn't 408/429 — let the SDK
        exception bubble up unchanged. _translate_arg_error returns
        normally; the caller then re-raises the original."""
        from defender_pipeline.azure.resource_graph import _translate_arg_error
        exc = self._fake_exc(status_code=403, message="forbidden")
        _translate_arg_error(exc)  # does not raise — caller handles


# ═══════════════════════════════════════════════════════════════════════════
# CLI scan subcommand — mocked run_scan
# ═══════════════════════════════════════════════════════════════════════════


class TestCliScan:
    def test_scan_invokes_run_scan_and_returns_ok(self) -> None:
        from defender_pipeline import cli
        args = MagicMock()
        args.acr_name = "myacr"
        args.min_score = 9.0
        args.max_score = 10.0
        args.repository = None
        args.repositories = None
        args.scan_image = None
        args.skip_tags = True
        args.output = "out.csv"
        args.parallelism = 8
        args.log_format = "text"
        args.log_level = "INFO"

        with patch("defender_pipeline.findings.scan.run_scan", return_value=42) as mock_run, \
             patch("defender_pipeline.logging_setup.setup"):
            rc = cli.cmd_scan(args)
        assert rc == cli.EXIT_OK
        mock_run.assert_called_once()

    def test_scan_returns_error_on_exception(self) -> None:
        from defender_pipeline import cli
        args = MagicMock()
        args.acr_name = "myacr"
        args.min_score = 9.0
        args.max_score = 10.0
        args.repository = None
        args.repositories = None
        args.scan_image = None
        args.skip_tags = True
        args.output = "out.csv"
        args.parallelism = 8
        args.log_format = "text"
        args.log_level = "INFO"

        with patch("defender_pipeline.findings.scan.run_scan",
                   side_effect=RuntimeError("boom")), \
             patch("defender_pipeline.logging_setup.setup"):
            rc = cli.cmd_scan(args)
        assert rc == cli.EXIT_ERROR

    def test_parse_scan_image_ref(self) -> None:
        from defender_pipeline.cli import _parse_scan_image_ref
        assert _parse_scan_image_ref(None) == (None, None)
        assert _parse_scan_image_ref("app") == ("app", None)
        assert _parse_scan_image_ref("app:latest") == ("app", None)
        assert _parse_scan_image_ref("app@sha256:abc") == ("app", "sha256:abc")


# ═══════════════════════════════════════════════════════════════════════════
# Diff subcommand
# ═══════════════════════════════════════════════════════════════════════════


class TestCliDiff:
    def test_identical_csvs_exit_0(self, tmp_path: Path) -> None:
        a = tmp_path / "a.csv"
        b = tmp_path / "b.csv"
        content = '"col1","col2"\n"v1","v2"\n'
        a.write_text(content)
        b.write_text(content)
        r = subprocess.run(
            [sys.executable, "-m", "defender_pipeline", "diff",
             "--bash-csv", str(a), "--python-csv", str(b)],
            cwd=REPO_ROOT, env={"PYTHONPATH": str(REPO_ROOT), "PATH": "/usr/bin:/bin"},
            capture_output=True, text=True, check=False,
        )
        assert r.returncode == 0, r.stderr
        assert "identical" in r.stderr

    def test_differing_csvs_exit_1(self, tmp_path: Path) -> None:
        a = tmp_path / "a.csv"
        b = tmp_path / "b.csv"
        a.write_text('"col1"\n"v1"\n')
        b.write_text('"col1"\n"v2"\n')
        r = subprocess.run(
            [sys.executable, "-m", "defender_pipeline", "diff",
             "--bash-csv", str(a), "--python-csv", str(b)],
            cwd=REPO_ROOT, env={"PYTHONPATH": str(REPO_ROOT), "PATH": "/usr/bin:/bin"},
            capture_output=True, text=True, check=False,
        )
        assert r.returncode == 1
        assert "differing" in r.stderr or "CSVs differ" in r.stderr

    def test_missing_file_exits_1(self, tmp_path: Path) -> None:
        r = subprocess.run(
            [sys.executable, "-m", "defender_pipeline", "diff",
             "--bash-csv", str(tmp_path / "nope.csv"),
             "--python-csv", str(tmp_path / "also-nope.csv")],
            cwd=REPO_ROOT, env={"PYTHONPATH": str(REPO_ROOT), "PATH": "/usr/bin:/bin"},
            capture_output=True, text=True, check=False,
        )
        assert r.returncode == 1
        assert "not found" in r.stderr
