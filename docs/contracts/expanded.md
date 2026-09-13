# `expanded.csv` — contract

**Producer:** `expandcsv.py`.
**Input:** `resultado_cruzamento.csv` (grouped) + `vulnerable_images_report.csv` (per-CVE).
**Row cardinality:** one row per unique `(namespace, parent_type, parent_name, repository, digest, cveId)` — the aggregated `CVE_LIST` from the grouped input is exploded and each CVE is enriched by lookup into `vulnerable_images_report.csv`.
**Encoding:** UTF-8, LF line endings.

## Header (exact string)

```csv
NAMESPACE,PARENT_TYPE,PARENT_NAME,REPOSITORY,DIGEST,TAG,CVE_ID,CVSS_SCORE,SEVERITY,PACKAGE_CATEGORY,PACKAGE_LANGUAGE,PACKAGE_NAME,CURRENT_VERSION,FIXED_VERSION,PATCHABLE,REMEDIATION,FIX_STATUS,CVE_AGE_DAYS,IS_IN_EXPLOIT_KIT,HAS_PUBLISHED_EXPLOIT,HAS_VERIFIED_EXPLOIT,LAST_PUSHED_TO_REGISTRY_UTC
```

## Columns (22)

| # | Name | Type | Origin |
|---|---|---|---|
| 1 | `NAMESPACE` | string | `resultado_cruzamento.NAMESPACE` |
| 2 | `PARENT_TYPE` | string | `resultado_cruzamento.PARENT_TYPE` |
| 3 | `PARENT_NAME` | string | `resultado_cruzamento.PARENT_NAME` |
| 4 | `REPOSITORY` | string | `resultado_cruzamento.REPOSITORY` |
| 5 | `DIGEST` | string | `resultado_cruzamento.DIGEST` |
| 6 | `TAG` | string | `resultado_cruzamento.TAG` |
| 7 | `CVE_ID` | string | exploded from `resultado_cruzamento.CVE_LIST` |
| 8 | `CVSS_SCORE` | number-as-string | `vulnerable_images_report.cvssScore` (lookup) |
| 9 | `SEVERITY` | string | `vulnerable_images_report.severity` (lookup) |
| 10 | `PACKAGE_CATEGORY` | string | idem |
| 11 | `PACKAGE_LANGUAGE` | string | idem |
| 12 | `PACKAGE_NAME` | string | idem |
| 13 | `CURRENT_VERSION` | string | idem |
| 14 | `FIXED_VERSION` | string | idem |
| 15 | `PATCHABLE` | string | idem |
| 16 | `REMEDIATION` | string | idem |
| 17 | `FIX_STATUS` | string | idem |
| 18 | `CVE_AGE_DAYS` | integer-as-string | idem |
| 19 | `IS_IN_EXPLOIT_KIT` | `"true"`/`"false"` | idem |
| 20 | `HAS_PUBLISHED_EXPLOIT` | `"true"`/`"false"` | idem |
| 21 | `HAS_VERIFIED_EXPLOIT` | `"true"`/`"false"` | idem |
| 22 | `LAST_PUSHED_TO_REGISTRY_UTC` | string (date) | idem |

## Lookup semantics

`expandcsv.py` uses a **3-level lookup ladder** to tolerate multi-arch manifests where the digest recorded in Defender may not match the digest OpenShift reports:

1. Full match on `(repository, digest, cveId)`.
2. Match on `(repository, cveId)` if no full match — picks the first fixed version found.
3. Match on `(repository, digest_prefix, cveId)` for short-digest cases.

This ladder is frozen behavior: the Python migration must preserve it (or explicitly document and get approval for a replacement).

## Guardrails

- `tests/test_contracts.py::TestExpandedContract` — header parity between `expandcsv.py:OUTPUT_FIELDS` and the canonical spec.
- `tests/test_expandcsv_unit.py` — lookup ladder behavior.
