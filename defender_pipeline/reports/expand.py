"""Grouped CSV → one row per CVE.

Port of ``expandcsv.py`` into the pipeline package. Preserves the
3-level lookup ladder that tolerates multi-arch digest mismatches:

    1. ``(repository, digest, cveId)`` — exact match.
    2. ``(repository, cveId)`` — falls back when Defender indexed a
       platform-specific child digest while the cluster reported the
       manifest-list top-level digest (or vice-versa).
    3. ``(repository, digest[:16], cveId)`` — tolerates minor digest
       truncation across sources.

Output contract: :mod:`defender_pipeline.reports.csv_contracts`
(22 columns, LF, UTF-8, ``csv.QUOTE_ALL``). See
``docs/contracts/expanded.md``.
"""
from __future__ import annotations

import csv
import logging
from dataclasses import dataclass
from pathlib import Path

from defender_pipeline.reports.csv_contracts import EXPANDED_HEADER_COLUMNS

logger = logging.getLogger(__name__)

# Defender source columns → expanded output columns. Order matters: the
# two lists are zipped 1-for-1 when materialising the lookup index.
_DEFENDER_SRC_COLUMNS: list[str] = [
    "cvssScore", "severity",
    "packageCategory", "packageLanguage", "packageName",
    "currentVersion", "fixedVersion", "patchable",
    "remediation", "fixStatus", "cveAgeDays",
    "isInExploitKit", "hasPublishedExploit", "hasVerifiedExploit",
    "lastPushedToRegistryUTC",
]

_DEFENDER_OUT_COLUMNS: list[str] = [
    "CVSS_SCORE", "SEVERITY",
    "PACKAGE_CATEGORY", "PACKAGE_LANGUAGE", "PACKAGE_NAME",
    "CURRENT_VERSION", "FIXED_VERSION", "PATCHABLE",
    "REMEDIATION", "FIX_STATUS", "CVE_AGE_DAYS",
    "IS_IN_EXPLOIT_KIT", "HAS_PUBLISHED_EXPLOIT", "HAS_VERIFIED_EXPLOIT",
    "LAST_PUSHED_TO_REGISTRY_UTC",
]

assert len(_DEFENDER_SRC_COLUMNS) == len(_DEFENDER_OUT_COLUMNS)

# Header columns that come straight from the grouped `resultado_cruzamento.csv`
_CRUZAMENTO_OUT_COLUMNS: list[str] = [
    "NAMESPACE", "PARENT_TYPE", "PARENT_NAME",
    "REPOSITORY", "DIGEST", "TAG", "CVE_ID",
]

# Sanity: the full expanded header is cruzamento cols + defender cols.
assert EXPANDED_HEADER_COLUMNS == _CRUZAMENTO_OUT_COLUMNS + _DEFENDER_OUT_COLUMNS


# ---------------------------------------------------------------------------
# Options + orchestration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExpandOptions:
    cruzamento: Path
    vulnerabilities: Path
    output: Path


def run_expand(opts: ExpandOptions) -> int:
    """Run the expand stage. Returns number of rows written."""
    if not opts.cruzamento.exists():
        raise FileNotFoundError(f"cruzamento CSV not found: {opts.cruzamento}")
    if not opts.vulnerabilities.exists():
        raise FileNotFoundError(f"vulnerabilities CSV not found: {opts.vulnerabilities}")

    logger.info("expand: loading vulnerabilities from %s", opts.vulnerabilities)
    idx_full, idx_digest, idx_prefix = load_vulnerability_data(opts.vulnerabilities)
    logger.info("expand: %d defender rows indexed", len(idx_full))

    logger.info("expand: exploding CVEs from %s", opts.cruzamento)
    rows = expand_cves(opts.cruzamento, idx_full, idx_digest, idx_prefix)
    logger.info("expand: %d expanded rows generated", len(rows))

    logger.info("expand: writing output to %s", opts.output)
    write_output(rows, opts.output)
    return len(rows)


# ---------------------------------------------------------------------------
# Helpers — kept small and testable
# ---------------------------------------------------------------------------


def get_field(row: dict, *names: str, default: str = "") -> str:
    """Return the first non-empty value among ``names``.

    Supports both uppercase legacy (``NAMESPACE``) and lowercase new
    (``namespace``) schema in the same reader.
    """
    for name in names:
        value = row.get(name)
        if value not in (None, ""):
            return value
    return default


def split_cves(value: str | None) -> list[str]:
    """Split a comma-separated CVE list; strip whitespace; dedupe preserving order."""
    seen: set[str] = set()
    out: list[str] = []
    for item in (value or "").split(","):
        cve = item.strip()
        if not cve or cve in seen:
            continue
        seen.add(cve)
        out.append(cve)
    return out


LookupIndex = tuple[
    dict[tuple[str, str, str], dict[str, str]],
    dict[tuple[str, str], dict[str, str]],
    dict[tuple[str, str, str], dict[str, str]],
]


def load_vulnerability_data(filepath: Path) -> LookupIndex:
    """Build the 3-level index from a defender vulnerabilities CSV."""
    idx_full: dict[tuple[str, str, str], dict[str, str]] = {}
    idx_digest: dict[tuple[str, str], dict[str, str]] = {}
    idx_prefix: dict[tuple[str, str, str], dict[str, str]] = {}

    with open(filepath, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        required = {"repository", "digest", "cveId"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(
                f"{filepath} is missing required defender.sh columns: "
                f"{', '.join(sorted(missing))}"
            )

        for row in reader:
            repository = get_field(row, "repository")
            digest = get_field(row, "digest")
            cve_id = get_field(row, "cveId")
            if not repository or not digest or not cve_id:
                continue

            detail: dict[str, str] = {
                out: row.get(src, "") or ""
                for src, out in zip(
                    _DEFENDER_SRC_COLUMNS, _DEFENDER_OUT_COLUMNS, strict=True
                )
            }
            detail["TAG"] = row.get("tag", row.get("TAG", "")) or ""

            idx_full[(repository, digest, cve_id)] = detail
            idx_digest.setdefault((repository, cve_id), detail)
            prefix = digest.replace("sha256:", "")[:16]
            idx_prefix.setdefault((repository, prefix, cve_id), detail)

    return idx_full, idx_digest, idx_prefix


def _lookup(
    idx_full: dict[tuple[str, str, str], dict[str, str]],
    idx_digest: dict[tuple[str, str], dict[str, str]],
    idx_prefix: dict[tuple[str, str, str], dict[str, str]],
    repository: str,
    digest: str,
    cve_id: str,
) -> dict[str, str]:
    """3-level lookup: full → (repo, cve) fallback → digest-prefix fallback."""
    hit = idx_full.get((repository, digest, cve_id))
    if hit is not None:
        return hit
    hit = idx_digest.get((repository, cve_id))
    if hit is not None:
        return hit
    prefix = digest.replace("sha256:", "")[:16]
    return idx_prefix.get((repository, prefix, cve_id), {})


def expand_cves(
    cruzamento_file: Path,
    idx_full: dict[tuple[str, str, str], dict[str, str]],
    idx_digest: dict[tuple[str, str], dict[str, str]],
    idx_prefix: dict[tuple[str, str, str], dict[str, str]],
) -> list[dict[str, str]]:
    """Explode grouped rows into one enriched row per unique CVE."""
    rows_expanded: list[dict[str, str]] = []
    emitted: set[tuple[str, str, str, str, str, str]] = set()

    with open(cruzamento_file, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError(f"{cruzamento_file} has no CSV header")

        for row in reader:
            namespace   = get_field(row, "NAMESPACE", "namespace")
            parent_type = get_field(row, "PARENT_TYPE", "parent_type")
            parent_name = get_field(row, "PARENT_NAME", "parent_name")
            repository  = get_field(row, "REPOSITORY", "repository")
            digest      = get_field(row, "DIGEST", "digest")
            tag         = get_field(row, "TAG", "tag")
            cve_list    = get_field(row, "CVE_LIST", "cve_list")

            if not repository or not digest:
                continue

            sev_map: dict[str, str] = {}
            raw_sev_map = get_field(row, "CVE_SEVERITY_MAP", "cve_severity_map")
            for entry in raw_sev_map.split(";"):
                if ":" in entry:
                    k, v = entry.split(":", 1)
                    sev_map[k.strip()] = v.strip()

            for cve_id in split_cves(cve_list):
                unique_key = (namespace, parent_type, parent_name, repository, digest, cve_id)
                if unique_key in emitted:
                    continue
                emitted.add(unique_key)

                vuln_info = _lookup(idx_full, idx_digest, idx_prefix, repository, digest, cve_id)

                expanded_row: dict[str, str] = {
                    "NAMESPACE":   namespace,
                    "PARENT_TYPE": parent_type,
                    "PARENT_NAME": parent_name,
                    "REPOSITORY":  repository,
                    "DIGEST":      digest,
                    "TAG":         tag or vuln_info.get("TAG", ""),
                    "CVE_ID":      cve_id,
                }

                for out_col in _DEFENDER_OUT_COLUMNS:
                    val = vuln_info.get(out_col, "")
                    if out_col == "SEVERITY" and (not val or val == "N/A"):
                        val = sev_map.get(cve_id, "N/A")
                    expanded_row[out_col] = val if val not in (None, "") else "N/A"

                rows_expanded.append(expanded_row)

    return rows_expanded


def write_output(rows: list[dict[str, str]], output_file: Path) -> None:
    """Write the expanded rows with the frozen 22-column header, QUOTE_ALL."""
    with open(output_file, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=EXPANDED_HEADER_COLUMNS, quoting=csv.QUOTE_ALL
        )
        writer.writeheader()
        writer.writerows(rows)
