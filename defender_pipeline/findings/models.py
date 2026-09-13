"""Dataclasses for the scan pipeline.

Boundaries:
  * :class:`DigestPair`   — output of Phase 0 (enumerate).
  * :class:`AssessmentRow` — output of Phase 2a (batched assessments).
    14 base fields + 6 ``inline_*`` fallbacks (used when cvedetails
    cannot enrich a given CVE — identity without MG scope, rejected
    CVE, etc.).
  * :class:`EnrichmentRow` — output of Phase 2c (batched cvedetails).
  * :class:`Finding`      — final CSV row shape (19 cols in the exact
    order of ``findings.csv_contracts.VULNERABLE_IMAGES_HEADER_COLUMNS``).

All are frozen so they can be used as dict keys / in sets.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class DigestPair:
    """A unique (repository, digest) pair from Phase 0."""

    repository: str
    digest: str

    @property
    def key(self) -> str:
        """Format used everywhere else as the tag-cache key."""
        return f"{self.repository}@{self.digest}"


@dataclass(frozen=True, slots=True)
class AssessmentRow:
    """One row from the batched assessments query (Phase 2a)."""

    # Identity
    repository: str
    digest: str
    cve_id: str
    # Package
    package_name: str
    current_version: str
    fixed_version: str
    fix_status: str
    package_category: str
    package_language: str
    remediation: str
    last_pushed_to_registry_utc: str
    # Inline fallbacks (used when enrichment misses)
    inline_severity: str = ""
    inline_cvss_base: float = 0.0
    inline_published_date: str = ""
    inline_in_exploit_kit: str = ""
    inline_publicly_disclosed: str = ""
    inline_verified: str = ""

    @classmethod
    def from_arg_row(cls, row: dict[str, Any]) -> AssessmentRow:
        """Build from a raw ARG response row (keys match KQL projection)."""
        def s(key: str) -> str:
            v = row.get(key)
            return "" if v is None else str(v)

        def f(key: str) -> float:
            v = row.get(key)
            if v is None or v == "":
                return 0.0
            try:
                return float(v)
            except (TypeError, ValueError):
                return 0.0

        return cls(
            repository=s("repository"),
            digest=s("digest"),
            cve_id=s("cveId"),
            package_name=s("packageName"),
            current_version=s("currentVersion"),
            fixed_version=s("fixedVersion"),
            fix_status=s("fixStatus"),
            package_category=s("packageCategory"),
            package_language=s("packageLanguage"),
            remediation=s("remediation"),
            last_pushed_to_registry_utc=s("lastPushedToRegistryUTC"),
            inline_severity=s("inlineSeverity"),
            inline_cvss_base=f("inlineCvssBase"),
            inline_published_date=s("inlinePublishedDate"),
            inline_in_exploit_kit=s("inlineInExploitKit"),
            inline_publicly_disclosed=s("inlinePubliclyDisclosed"),
            inline_verified=s("inlineVerified"),
        )


@dataclass(frozen=True, slots=True)
class EnrichmentRow:
    """One row from the batched cvedetails query (Phase 2c).

    ``cve_id_join`` is always upper-cased (KQL uses ``toupper``).
    """

    cve_id_join: str
    cvss: float | None
    published_date: str
    severity: str
    verified: int
    publicly_disclosed: int
    in_exploit_kit: int

    @classmethod
    def from_arg_row(cls, row: dict[str, Any]) -> EnrichmentRow:
        def s(key: str) -> str:
            v = row.get(key)
            return "" if v is None else str(v)

        def i(key: str) -> int:
            v = row.get(key)
            if v is None or v == "":
                return 0
            try:
                return int(v)
            except (TypeError, ValueError):
                return 0

        cvss = row.get("cvssEnrich")
        cvss_float: float | None
        try:
            cvss_float = float(cvss) if cvss not in (None, "") else None
        except (TypeError, ValueError):
            cvss_float = None

        return cls(
            cve_id_join=s("cveIdJoin").upper(),
            cvss=cvss_float,
            published_date=s("publishedDateEnrich"),
            severity=s("severityEnrich"),
            verified=i("verifiedExpEnrich"),
            publicly_disclosed=i("publishedExpEnrich"),
            in_exploit_kit=i("inExploitKitEnrich"),
        )


@dataclass(frozen=True, slots=True)
class Finding:
    """Final CSV row — 19 fields in the exact order of
    ``findings.csv_contracts.VULNERABLE_IMAGES_HEADER_COLUMNS``."""

    repository: str
    digest: str
    tag: str
    cvss_score: str          # printed with %g so csv matches bash
    cve_id: str
    severity: str
    package_category: str
    package_language: str
    package_name: str
    current_version: str
    fixed_version: str
    patchable: str
    remediation: str
    fix_status: str
    cve_age_days: str
    is_in_exploit_kit: str    # "true" / "false"
    has_published_exploit: str
    has_verified_exploit: str
    last_pushed_to_registry_utc: str

    def as_csv_values(self) -> list[str]:
        """Ordered list matching the 19-column CSV contract."""
        return [
            self.repository, self.digest, self.tag, self.cvss_score,
            self.cve_id, self.severity, self.package_category,
            self.package_language, self.package_name, self.current_version,
            self.fixed_version, self.patchable, self.remediation,
            self.fix_status, self.cve_age_days, self.is_in_exploit_kit,
            self.has_published_exploit, self.has_verified_exploit,
            self.last_pushed_to_registry_utc,
        ]
