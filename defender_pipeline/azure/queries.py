"""KQL query builders — Python-side ports of the bash builders in
``defender.sh``.

Kept as pure functions (input = args, output = KQL string) so they are
trivially unit-testable without touching Azure at all.

Design notes preserved from the bash implementation:

  * Enumerate query (`build_enumerate_digests_query`) — cheap query that
    lists unique (repository, digest) pairs matching the early filter.
    Drives Phase 2 per-batch scan.
  * Batched assessments (`build_batched_assessments_query`) — no JOIN
    with `microsoft.security/cvedetails`. Emits 14 base fields + 6
    inline fallbacks. Batch of ~50 digests stays under ARG complexity.
  * Batched cvedetails (`build_batched_cvedetails_query`) — enrichment
    only. Batch of ~500 CVE IDs. `cveIdJoin` is upper-cased so the
    downstream merge can do a case-insensitive dict lookup.

See ``docs/mdvm-two-phase-benchmark.md`` for the full architecture and
``erros.md`` for the schema gotchas (no ``cvss["3.1"]`` key, etc).
"""
from __future__ import annotations

from collections.abc import Sequence


def _kql_string_list(items: Sequence[str]) -> str:
    """Build a KQL `in (...)` list expression from Python strings.

    Filters out any item containing ``"`` or ``\\`` (defensive against
    KQL injection — the pipeline only passes digest hashes and CVE
    IDs, which are hex or ``CVE-NNNN-NNNNN``).
    """
    safe = [item for item in items if '"' not in item and "\\" not in item]
    return ", ".join(f'"{item}"' for item in safe)


def build_enumerate_digests_query(filter_kql: str = "") -> str:
    """Query that lists unique (repository, digest) pairs.

    Args:
        filter_kql: optional KQL fragment appended after the type/category
            filters — used by ``--repository`` / ``--repositories`` /
            ``--scan-image`` to push the filter down to ARG.
    """
    return f"""securityresources
| where type == "microsoft.security/assessments"
| where properties.metadata.recommendationCategory == "SoftwareUpdate"
| where properties.resourceDetails.ResourceType == ".containerimage"
| where properties.resourceDetails.Source == "Azure"
{filter_kql}
| extend _image = parse_json(tostring(properties.resourceAdditionalData))
| extend
    _repository = tostring(_image.RepositoryDetails.RepositoryName),
    _digest     = tostring(_image.Digest)
| where isnotempty(_digest)
| distinct _repository, _digest"""


def build_batched_assessments_query(digests: Sequence[str]) -> str:
    """Assessments query for a batch of digests. NO JOIN — cheap.

    Emits 14 base fields the merger needs plus 6 ``inline*`` fallbacks
    used when enrichment can't reach a given CVE (identity without MG
    scope, rejected CVE, etc.).
    """
    digest_list = _kql_string_list(digests)
    return f"""securityresources
| where type == "microsoft.security/assessments"
| where properties.metadata.recommendationCategory == "SoftwareUpdate"
| where properties.resourceDetails.ResourceType == ".containerimage"
| where properties.resourceDetails.Source == "Azure"
| extend
    _scanner = parse_json(tostring(properties.additionalData.ScannersDetails)),
    _image   = parse_json(tostring(properties.resourceAdditionalData)),
    _cves    = parse_json(tostring(properties.additionalData.CvesDetails))
| extend _digest = tostring(_image.Digest)
| where _digest in ({digest_list})
| mv-expand cve = _cves
| extend cveId = coalesce(tostring(cve.CveId), tostring(cve.cveId))
| where isnotempty(cveId) and cveId startswith "CVE-"
| project
    repository = tostring(_image.RepositoryDetails.RepositoryName),
    digest = _digest,
    cveId,
    packageName = tostring(coalesce(
        properties.additionalData.SoftwareName,
        properties.additionalData.softwareName
    )),
    currentVersion = case(
        array_length(_scanner.mdvm.DetectedSoftwareVersions) > 0,
            strcat_array(_scanner.mdvm.DetectedSoftwareVersions, ", "),
        array_length(_scanner.agentlessmdvm.DetectedSoftwareVersions) > 0,
            strcat_array(_scanner.agentlessmdvm.DetectedSoftwareVersions, ", "),
        tostring(properties.additionalData.DetectedSoftwareVersions)
    ),
    fixedVersion = tostring(coalesce(
        _scanner.mdvm.FixedVersion,
        _scanner.agentlessmdvm.FixedVersion,
        properties.additionalData.FixedVersion,
        cve.FixedVersion,
        cve.fixedVersion
    )),
    fixStatus = tostring(coalesce(
        cve.FixStatus,
        cve.fixStatus,
        properties.additionalData.FixStatus,
        _scanner.mdvm.FixStatus
    )),
    packageCategory = tostring(coalesce(
        properties.additionalData.PackageType,
        _scanner.mdvm.category,
        _scanner.mdvm.PackageType
    )),
    packageLanguage = tostring(coalesce(
        properties.additionalData.Language,
        _scanner.mdvm.Language
    )),
    remediation = tostring(coalesce(
        cve.Description,
        properties.remediation,
        properties.description
    )),
    lastPushedToRegistryUTC = tostring(coalesce(
        _image.LastPushedToRegistryUTC,
        _image.RepositoryDetails.LastPushedToRegistryUTC
    )),
    inlineSeverity = tostring(cve.Severity),
    inlineCvssBase = todouble(cve.Cvss[0].Value.Base),
    inlinePublishedDate = tostring(cve.PublishedDate),
    inlineInExploitKit = tostring(cve.ExploitabilityDetails.IsInExploitKit),
    inlinePubliclyDisclosed = tostring(coalesce(
        cve.ExploitabilityDetails.ExploitStepsPublished,
        cve.ExploitabilityDetails.IsPubliclyDisclosed
    )),
    inlineVerified = tostring(coalesce(
        cve.ExploitabilityDetails.ExploitStepsVerified,
        cve.ExploitabilityDetails.IsVerified
    ))
| distinct
    repository, digest, cveId, packageName, currentVersion, fixedVersion,
    fixStatus, packageCategory, packageLanguage, remediation, lastPushedToRegistryUTC,
    inlineSeverity, inlineCvssBase, inlinePublishedDate,
    inlineInExploitKit, inlinePubliclyDisclosed, inlineVerified"""


def build_batched_cvedetails_query(cve_ids: Sequence[str]) -> str:
    """Cvedetails enrichment for a batch of CVE IDs.

    ``cveIdJoin`` is upper-cased so the Python merger can do a case-
    insensitive lookup (CVE ids may differ in case between assessments
    like ``CVE-2024-1234`` and cvedetails names like ``cve-2024-1234``).
    """
    cveid_list = _kql_string_list(cve_ids)
    return f"""securityresources
| where type =~ "microsoft.security/cvedetails"
| where tostring(properties.status) !~ "Reject"
| extend cveIdJoin = toupper(coalesce(tostring(properties.cveId), tostring(name)))
| where cveIdJoin in ({cveid_list})
| extend _cvss40 = todouble(properties.cvss["4.0"].base)
| extend _cvss30 = todouble(properties.cvss["3.0"].base)
| extend _cvss20 = todouble(properties.cvss["2.0"].base)
| extend cvssEnrich = coalesce(_cvss40, _cvss30, _cvss20)
| extend publishedDateEnrich = tostring(properties.publishedDate)
| extend severityEnrich = tostring(properties.severity)
| extend verifiedExpEnrich = iff(isnull(properties.exploitabilityDetails.IsVerified), false, tobool(properties.exploitabilityDetails.IsVerified))
| extend publishedExpEnrich = iff(isnull(properties.exploitabilityDetails.IsPubliclyDisclosed), false, tobool(properties.exploitabilityDetails.IsPubliclyDisclosed))
| extend inExploitKitEnrich = iff(isnull(properties.exploitabilityDetails.IsInExploitKit), false, tobool(properties.exploitabilityDetails.IsInExploitKit))
| summarize
    cvssEnrich = max(cvssEnrich),
    publishedDateEnrich = take_any(publishedDateEnrich),
    severityEnrich = take_any(severityEnrich),
    verifiedExpEnrich = max(toint(verifiedExpEnrich)),
    publishedExpEnrich = max(toint(publishedExpEnrich)),
    inExploitKitEnrich = max(toint(inExploitKitEnrich))
  by cveIdJoin
| project cveIdJoin, cvssEnrich, publishedDateEnrich, severityEnrich,
          verifiedExpEnrich, publishedExpEnrich, inExploitKitEnrich"""


# ---------------------------------------------------------------------------
# Scope filter builders (mirror EARLY_FILTER_B in defender.sh)
# ---------------------------------------------------------------------------


def repo_to_dashed_path(repository: str) -> str:
    """Convert an ACR repo path to the dashed form Defender uses inside
    ``resourceDetails.Id``. Same as bash's ``repo_to_dashed_path``.

    Example: ``base-images/ubi9-openjdk17`` → ``base-images-ubi9-openjdk17``.
    """
    return repository.replace("/", "-")


def build_scope_filter(
    repository: str | None = None,
    repositories: Sequence[str] | None = None,
    scan_repository: str | None = None,
    scan_digest: str | None = None,
) -> str:
    """Return the KQL filter fragment to push a scope filter down to ARG.

    Priority (matches ``defender.sh``):

        1. ``--scan-image`` (with optional digest) — most specific.
        2. ``--repository`` — substring contains match.
        3. ``--repositories`` — anchored exact match on the
           ``repositories-<dashed>-images-`` segment.

    Returns an empty string when no scope filter is requested.
    """
    if scan_repository:
        dashed = repo_to_dashed_path(scan_repository)
        expr = f'| where properties.resourceDetails.Id contains "{dashed}"'
        if scan_digest:
            digest_hex = scan_digest.removeprefix("sha256:")
            expr += f' and properties.resourceDetails.Id contains "{digest_hex}"'
        return expr

    if repository:
        dashed = repo_to_dashed_path(repository)
        return f'| where properties.resourceDetails.Id contains "{dashed}"'

    if repositories:
        parts = []
        for repo in repositories:
            dashed = repo_to_dashed_path(repo)
            parts.append(
                f'properties.resourceDetails.Id contains '
                f'"repositories-{dashed}-images-"'
            )
        return "| where " + " or ".join(parts)

    return ""
