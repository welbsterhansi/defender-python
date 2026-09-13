# `vulnerable_images_report.csv` — contract

**Producer:** `defender.sh` (Phase 2d writer is `enrich_cvedetails.py`).
**Row cardinality:** one row per unique `(repository, digest, cveId, packageName, currentVersion, fixedVersion, ...)` combination — the KQL `| distinct` clause enforces this.
**Encoding:** UTF-8, LF line endings.
**Quoting:** every field wrapped in `"..."`. Internal `"` becomes `'`. Internal newlines and CR collapsed to a single space (see `csv_field()` in `defender.sh:40-46` and mirrored in `enrich_cvedetails.py`).

## Header (exact string)

```csv
"repository","digest","tag","cvssScore","cveId","severity","packageCategory","packageLanguage","packageName","currentVersion","fixedVersion","patchable","remediation","fixStatus","cveAgeDays","isInExploitKit","hasPublishedExploit","hasVerifiedExploit","lastPushedToRegistryUTC"
```

## Columns (19)

| # | Name | Type | Source | Notes |
|---|---|---|---|---|
| 1 | `repository` | string | `_image.RepositoryDetails.RepositoryName` | ACR repository path (e.g. `base-images/env0`) |
| 2 | `digest` | string | `_image.Digest` | `sha256:...` (64 hex chars) |
| 3 | `tag` | string | `az acr repository show-tags` | Resolved once per unique repo. `--skip-tags` forces `"N/A"`. |
| 4 | `cvssScore` | number-as-string | coalesce: enrichment → inline → severity fallback | `9.8`, `7.0`, etc. — printed with `%g` |
| 5 | `cveId` | string | `cve.CveId` (or `cve.cveId`) | Always starts with `CVE-` (rows failing that predicate are dropped) |
| 6 | `severity` | string | `severityRaw` (enrichment or inline) → `classify_severity(cvss)` fallback | `Critical`/`High`/`Medium`/`Low`/`None` |
| 7 | `packageCategory` | string | coalesce: `properties.additionalData.PackageType`, `_scanner.mdvm.category`, `_scanner.mdvm.PackageType` | e.g. `OS`, `DevPackage` |
| 8 | `packageLanguage` | string | coalesce: `properties.additionalData.Language`, `_scanner.mdvm.Language` | e.g. `java`, `Java`, empty for OS packages |
| 9 | `packageName` | string | coalesce: `SoftwareName`, `softwareName` | e.g. `openssl`, `postgresql-jdbc` |
| 10 | `currentVersion` | string | `_scanner.mdvm.DetectedSoftwareVersions` (all, comma-joined) or fallback ladder | e.g. `1.0.2, 1.0.3` |
| 11 | `fixedVersion` | string | coalesce (6 sources: `_scanner.mdvm/agentlessmdvm.FixedVersion`, `additionalData.FixedVersion`, `cve.FixedVersion`, `cve.fixedVersion`) | e.g. `2.0`, empty when no fix |
| 12 | `patchable` | `"true"`/`"false"`/`""` | derived from `fixStatus` and `fixedVersion` | see logic in `defender.sh:970` / `enrich_cvedetails.compute_patchable` |
| 13 | `remediation` | string | coalesce: `cve.Description`, `properties.remediation`, `properties.description` | Free text; internal newlines collapsed to space |
| 14 | `fixStatus` | string | coalesce (4 sources) | `FixAvailable`, `NoFix`, `NoFixAvailable`, `WillNotFix`, empty |
| 15 | `cveAgeDays` | integer-as-string | `datetime_diff('day', now(), publishedDate)` or `-1` when unknown | e.g. `935`, `-1` |
| 16 | `isInExploitKit` | `"true"`/`"false"` | `properties.exploitabilityDetails.IsInExploitKit` (enrichment) or `cve.ExploitabilityDetails.IsInExploitKit` (inline) | K chip in HTML |
| 17 | `hasPublishedExploit` | `"true"`/`"false"` | `properties.exploitabilityDetails.IsPubliclyDisclosed` (enrichment) or coalesce inline (`ExploitStepsPublished`, `IsPubliclyDisclosed`) | P chip |
| 18 | `hasVerifiedExploit` | `"true"`/`"false"` | `properties.exploitabilityDetails.IsVerified` (enrichment) or coalesce inline (`ExploitStepsVerified`, `IsVerified`) | V chip |
| 19 | `lastPushedToRegistryUTC` | string (date) | coalesce: `_image.LastPushedToRegistryUTC`, `_image.RepositoryDetails.LastPushedToRegistryUTC` | Free-form; format may vary by Azure sample |

## Filters applied

- `where cveId startswith "CVE-"` — non-CVE rows removed.
- `where cvssScore >= $MIN_SCORE and cvssScore <= $MAX_SCORE` — CLI band filter.
- `| distinct <all 18 non-tag fields>` — dedup (tag not part of the KQL, injected later by the shell).

## Row order (Python producer only)

The bash producer's KQL includes `| order by cvssScore desc, repository asc` at the query level. The Python producer splits that JOIN into batched assessments + cvedetails + local merge, which loses the KQL sort. To keep diffs, tests, and downstream consumers deterministic, the Python producer sorts before writing:

1. `cvssScore` **desc** (parsed as float; bash-compatible `%g` string used for tie compare)
2. `repository` asc
3. `digest` asc (tiebreak)
4. `cveId` asc (tiebreak)
5. `packageName` asc (tiebreak)

This is enforced by `defender_pipeline.findings.enrich.merge` and covered by `tests/test_defender_pipeline_scan.py::TestEnrichMerge::test_deterministic_sort_order` + `test_sort_is_stable_across_calls`. Order is a **soft contract for the Python producer** — the bash producer may drift when ARG re-orders its result set.

## Guardrails (tests that MUST pass)

- `tests/test_contracts.py::TestVulnerableImagesReportContract` — header parity between `defender.sh:769` and `enrich_cvedetails.CSV_HEADER_COLUMNS`.
- `tests/test_defender_batched_integration.py::TestCsvContract::test_header_exact_19_columns` — end-to-end assertion after a mocked scan.
- `tests/test_enrich_cvedetails.py::TestEnrichEndToEnd` — 77 unit tests covering formatting, coercers, dedup, fallbacks.
- `tests/test_defender_query_migration.py::TestCsvColumnOrderPreserved::test_project_column_list_matches` — the KQL `| project` inside `build_digest_scan_query` matches the 18 fields (tag added shell-side).

## Non-goals (things that MAY vary and are NOT part of the contract)

- Row ORDER within the CSV **for the bash producer** (bash relies on the KQL `order by`, which ARG may re-evaluate slightly differently under load — nice-to-have, not contract). Python producer has a stronger sort spec — see "Row order (Python producer only)" above.
- Exact value of `lastPushedToRegistryUTC` format (Azure has shipped multiple representations over time — parse tolerantly).
- Presence of specific CVE IDs (dependent on the ACR contents and Defender scan state).
