"""Local merge of assessments + cvedetails — Python-native replacement
of the bash-invoked ``enrich_cvedetails.py`` helper.

Merge key: upper-cased CVE ID. Fallback ladder for missing enrichment:
enrichment → inline (from assessments row) → severity-derived
(``cvss_from_severity``).

Filter: --min-score / --max-score applied post-enrichment.

The scoring/coercion helpers here are intentionally the SAME semantics
as ``enrich_cvedetails.py`` — that file is untouched during migration,
so both paths produce byte-identical CSVs. See
``tests/test_enrich_cvedetails.py`` for the reference behavior.
"""
from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from defender_pipeline.findings.models import (
    AssessmentRow,
    EnrichmentRow,
    Finding,
)


def classify_severity(score: float) -> str:
    """Mirror defender.sh:57-70 exactly."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "None"


def cvss_from_severity(severity: str) -> float:
    s = (severity or "").strip().lower()
    if s == "critical":
        return 9.0
    if s == "high":
        return 7.0
    if s == "medium":
        return 4.0
    if s == "low":
        return 0.1
    return 0.0


def compute_patchable(fix_status: str, fixed_version: str) -> str:
    """Mirror the KQL patchable case exactly."""
    s = (fix_status or "").strip().lower()
    if s == "fixavailable":
        return "true"
    if s in ("nofix", "nofixavailable", "willnotfix"):
        return "false"
    if (fixed_version or "").strip():
        return "true"
    return ""


def _parse_published_date(s: str) -> datetime | None:
    if not s:
        return None
    normalized = s.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _to_bool(value) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    return s in ("true", "1")


def _bool_str(value) -> str:
    return "true" if _to_bool(value) else "false"


def merge(
    assessments: Iterable[AssessmentRow],
    enrichment_by_cve: dict[str, EnrichmentRow],
    tag_by_pair: dict[str, str],
    *,
    min_score: float,
    max_score: float,
    now: datetime | None = None,
) -> list[Finding]:
    """Run the merge — produce a de-duplicated, filtered list of Findings.

    Args:
        assessments: rows from Phase 2a.
        enrichment_by_cve: dict keyed by upper(cveId) → EnrichmentRow.
        tag_by_pair: dict keyed by ``"{repo}@{digest}"`` → tag (default "N/A").
        min_score, max_score: CVSS filter applied post-enrichment.
        now: injectable "current time" for deterministic tests.
    """
    now = now or datetime.now(UTC)
    seen: set[tuple[str, ...]] = set()
    out: list[Finding] = []

    for row in assessments:
        cve_id = row.cve_id
        if not cve_id.startswith("CVE-"):
            continue

        enr = enrichment_by_cve.get(cve_id.upper())

        # Severity — enrichment > inline
        severity_raw = (enr.severity if enr else "").strip() or row.inline_severity.strip()

        # CVSS — enrichment > inline > severity-derived.
        # Always ends up as a float (0.0 in the worst case) after the ladder.
        cvss: float = (enr.cvss if (enr and enr.cvss is not None) else 0.0)
        if cvss == 0.0:
            cvss = (
                row.inline_cvss_base
                if row.inline_cvss_base > 0
                else cvss_from_severity(severity_raw)
            )

        # Filter
        if cvss < min_score or cvss > max_score:
            continue

        severity = severity_raw or classify_severity(cvss)

        # Published date → cveAgeDays
        published_str = ((enr.published_date if enr else "").strip()
                         or row.inline_published_date.strip())
        published_dt = _parse_published_date(published_str)
        cve_age_days = (now - published_dt).days if published_dt else -1

        # Exploit chips — enrichment > inline
        in_kit = _bool_str(enr.in_exploit_kit if enr else row.inline_in_exploit_kit)
        pub_exp = _bool_str(enr.publicly_disclosed if enr else row.inline_publicly_disclosed)
        ver_exp = _bool_str(enr.verified if enr else row.inline_verified)

        # Patchable
        patchable = compute_patchable(row.fix_status, row.fixed_version)

        # Tag lookup (missing → N/A)
        tag = tag_by_pair.get(f"{row.repository}@{row.digest}", "N/A")

        # CVSS printed with %g so it matches KQL `tostring(<double>)`
        cvss_str = f"{cvss:g}"

        # Distinct key = all 18 non-tag fields (matches KQL | distinct)
        distinct_key = (
            row.repository, row.digest, cvss_str, cve_id, severity,
            row.package_category, row.package_language, row.package_name,
            row.current_version, row.fixed_version, patchable,
            row.remediation, row.fix_status, str(cve_age_days),
            in_kit, pub_exp, ver_exp, row.last_pushed_to_registry_utc,
        )
        if distinct_key in seen:
            continue
        seen.add(distinct_key)

        out.append(Finding(
            repository=row.repository,
            digest=row.digest,
            tag=tag,
            cvss_score=cvss_str,
            cve_id=cve_id,
            severity=severity,
            package_category=row.package_category,
            package_language=row.package_language,
            package_name=row.package_name,
            current_version=row.current_version,
            fixed_version=row.fixed_version,
            patchable=patchable,
            remediation=row.remediation,
            fix_status=row.fix_status,
            cve_age_days=str(cve_age_days),
            is_in_exploit_kit=in_kit,
            has_published_exploit=pub_exp,
            has_verified_exploit=ver_exp,
            last_pushed_to_registry_utc=row.last_pushed_to_registry_utc,
        ))

    # Deterministic sort — replaces the KQL ``order by cvssScore desc,
    # repository asc`` we lost when the JOIN was split into batched
    # assessments + cvedetails + local merge. Tie-break on digest/cveId/
    # packageName so identical CVSS rows land in a stable, diff-friendly
    # order across runs.
    out.sort(key=lambda f: (
        -_safe_float(f.cvss_score),  # cvssScore desc
        f.repository,                 # repository asc
        f.digest,                     # digest asc (tiebreak)
        f.cve_id,                     # cveId asc (tiebreak)
        f.package_name,               # packageName asc (tiebreak)
    ))
    return out


def _safe_float(s: str) -> float:
    """cvss_score is stored as %g-formatted string; parse back for sort.
    Never raises — defensive because empty/malformed values shouldn't
    take down the whole scan."""
    try:
        return float(s)
    except (TypeError, ValueError):
        return 0.0
