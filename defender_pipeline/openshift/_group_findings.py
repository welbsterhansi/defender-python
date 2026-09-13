#!/usr/bin/env python3
"""
Group raw (namespace, workload, image, CVE) rows into one row per unique
(namespace, workload, image) with aggregated CVE fields.

Consumes the flat CSV produced by check_ocp.sh (each pod × image × matched
CVE = one row) and produces the grouped CSV consumed by expandcsv.py and
report.py.

Input schema  (from check_ocp.sh):
    NAMESPACE, PARENT_TYPE, PARENT_NAME,
    repository, digest, tag,
    cvssScore, cveId, severity,
    packageCategory, packageLanguage, packageName,
    currentVersion, fixedVersion, patchable, remediation, fixStatus,
    cveAgeDays, isInExploitKit, hasPublishedExploit, hasVerifiedExploit,
    lastPushedToRegistryUTC

Output schema (24 columns, uppercase):
    NAMESPACE, PARENT_TYPE, PARENT_NAME, REPOSITORY, DIGEST, TAG,
    CVE_COUNT, CRITICALITY, CVSS_SCORE, CVE_LIST, CVE_SEVERITY_MAP,
    PACKAGE_CATEGORY, PACKAGE_LANGUAGE, PACKAGE_NAME,
    CURRENT_VERSION, FIXED_VERSION, PATCHABLE, REMEDIATION, FIX_STATUS,
    CVE_AGE_DAYS, IS_IN_EXPLOIT_KIT, HAS_PUBLISHED_EXPLOIT,
    HAS_VERIFIED_EXPLOIT, LAST_PUSHED_TO_REGISTRY_UTC

Rationale for extraction (task #20): the previous inline `python3 -c '...'`
was untestable and duplicated shell-vs-python string escaping. This module
is a plain function that can be unit-tested and reused without spawning
a subprocess from bash.
"""
from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

OUTPUT_HEADER = [
    "NAMESPACE", "PARENT_TYPE", "PARENT_NAME", "REPOSITORY", "DIGEST", "TAG",
    "CVE_COUNT", "CRITICALITY", "CVSS_SCORE", "CVE_LIST", "CVE_SEVERITY_MAP",
    "PACKAGE_CATEGORY", "PACKAGE_LANGUAGE", "PACKAGE_NAME",
    "CURRENT_VERSION", "FIXED_VERSION", "PATCHABLE",
    "REMEDIATION", "FIX_STATUS", "CVE_AGE_DAYS",
    "IS_IN_EXPLOIT_KIT", "HAS_PUBLISHED_EXPLOIT", "HAS_VERIFIED_EXPLOIT",
    "LAST_PUSHED_TO_REGISTRY_UTC",
]

# Package/exploit fields we carry over from the flat rows. "Last non-empty
# value per group wins" — Defender may report the same CVE from multiple
# subassessments with slightly different metadata; picking the latest
# populated one is a good enough heuristic and matches the prior inline behavior.
CARRIED_FIELDS = (
    "packageCategory", "packageLanguage", "packageName",
    "currentVersion", "fixedVersion", "patchable",
    "fixStatus", "cveAgeDays", "isInExploitKit",
    "hasPublishedExploit", "hasVerifiedExploit", "lastPushedToRegistryUTC",
)


def _new_group() -> dict[str, Any]:
    """defaultdict factory — explicit type keeps pyright happy."""
    return {
        "cves": set(),
        "max_cvss": 0.0,
        "severities": set(),
        "cve_severity_map": {},
        "tag": "N/A",
        "remediation": "",
        **{col: "" for col in CARRIED_FIELDS},
        # Exploit flags default to "false" (matches Defender's convention).
        "isInExploitKit": "false",
        "hasPublishedExploit": "false",
        "hasVerifiedExploit": "false",
    }


def _parse_score(raw: str) -> float | None:
    """Parse cvssScore string → float, or None if unparseable."""
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def group_rows(flat_rows: list[dict[str, str]]) -> list[list[Any]]:
    """
    Aggregate flat rows into grouped rows.

    Returns a list of row-lists in OUTPUT_HEADER column order, ready to be
    passed to `csv.writer.writerows`.
    """
    data: dict[tuple[str, str, str, str, str], dict[str, Any]] = defaultdict(_new_group)

    for row in flat_rows:
        key = (
            row.get("NAMESPACE", ""),
            row.get("PARENT_TYPE", ""),
            row.get("PARENT_NAME", ""),
            row.get("repository", ""),
            row.get("digest", ""),
        )
        entry = data[key]

        cve_id   = row.get("cveId", "")
        severity = row.get("severity", "")
        entry["cves"].add(cve_id)
        entry["severities"].add(severity)
        entry["cve_severity_map"][cve_id] = severity

        tag = row.get("tag", "")
        if tag and tag not in ("N/A", ""):
            entry["tag"] = tag

        score = _parse_score(row.get("cvssScore", ""))
        if score is not None and score > entry["max_cvss"]:
            entry["max_cvss"] = score

        # Carry over: keep the last non-empty value seen for each field.
        for col in CARRIED_FIELDS:
            v = row.get(col, "")
            if v and v not in ("N/A", ""):
                entry[col] = v

        # Remediation: prefer the shortest non-empty text — avoids huge
        # AI-generated blobs polluting the summary row.
        rem = row.get("remediation", "")
        if rem and rem not in ("N/A", "") and (
            not entry["remediation"] or len(rem) < len(entry["remediation"])
        ):
            entry["remediation"] = rem

    out_rows: list[list[Any]] = []
    for (ns, kind, name, repo, digest), info in data.items():
        cve_list = ", ".join(sorted(info["cves"]))
        sev_list = ", ".join(sorted(info["severities"]))
        sev_map  = ";".join(
            f"{c}:{s}" for c, s in sorted(info["cve_severity_map"].items())
        )
        out_rows.append([
            ns, kind, name, repo, digest, info["tag"],
            len(info["cves"]), sev_list, info["max_cvss"], cve_list, sev_map,
            info["packageCategory"], info["packageLanguage"], info["packageName"],
            info["currentVersion"], info["fixedVersion"], info["patchable"],
            info["remediation"], info["fixStatus"], info["cveAgeDays"],
            info["isInExploitKit"], info["hasPublishedExploit"], info["hasVerifiedExploit"],
            info["lastPushedToRegistryUTC"],
        ])
    return out_rows


def group_file(input_path: str | Path, output_path: str | Path) -> int:
    """Read flat CSV → group → write grouped CSV. Return number of groups."""
    # csv module chokes on very large fields (e.g. long remediation blobs).
    csv.field_size_limit(sys.maxsize)

    with open(input_path, encoding="utf-8", newline="") as fin:
        rows = list(csv.DictReader(fin))
    grouped = group_rows(rows)
    with open(output_path, "w", encoding="utf-8", newline="") as fout:
        w = csv.writer(fout)
        w.writerow(OUTPUT_HEADER)
        w.writerows(grouped)
    return len(grouped)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Group flat (ns, workload, image, CVE) rows into per-workload rows.",
    )
    parser.add_argument("input", help="Flat CSV from check_ocp.sh")
    parser.add_argument("output", help="Grouped CSV to write")
    args = parser.parse_args()

    if not Path(args.input).exists():
        print(f"Erro: arquivo de entrada não encontrado: {args.input}", file=sys.stderr)
        return 1

    try:
        n = group_file(args.input, args.output)
    except Exception as exc:  # - operator-facing error
        print(f"Erro no processamento: {exc}", file=sys.stderr)
        return 1

    print(f"Sucesso! {n} grupo(s) salvos em: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
