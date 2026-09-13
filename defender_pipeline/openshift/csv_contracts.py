"""Frozen 24-column contract for ``resultado_cruzamento.csv``.

See ``docs/contracts/resultado_cruzamento.md``.
"""
from __future__ import annotations

RESULTADO_CRUZAMENTO_HEADER_COLUMNS: list[str] = [
    "NAMESPACE", "PARENT_TYPE", "PARENT_NAME",
    "REPOSITORY", "DIGEST", "TAG",
    "CVE_COUNT", "CRITICALITY", "CVSS_SCORE",
    "CVE_LIST", "CVE_SEVERITY_MAP",
    "PACKAGE_CATEGORY", "PACKAGE_LANGUAGE", "PACKAGE_NAME",
    "CURRENT_VERSION", "FIXED_VERSION", "PATCHABLE",
    "REMEDIATION", "FIX_STATUS", "CVE_AGE_DAYS",
    "IS_IN_EXPLOIT_KIT", "HAS_PUBLISHED_EXPLOIT", "HAS_VERIFIED_EXPLOIT",
    "LAST_PUSHED_TO_REGISTRY_UTC",
]

RESULTADO_CRUZAMENTO_COLUMN_COUNT: int = 24

assert len(RESULTADO_CRUZAMENTO_HEADER_COLUMNS) == RESULTADO_CRUZAMENTO_COLUMN_COUNT

# Platform-managed namespaces filtered from the correlation.
# See docs/contracts/cli-behavior.md — this list is frozen.
EXCLUDED_NAMESPACE_PATTERNS: list[str] = [
    "openshift-", "kube-", "default", "logging", "monitoring",
]
