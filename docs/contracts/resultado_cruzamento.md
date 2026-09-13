# `resultado_cruzamento.csv` — contract

**Producer:** `check_ocp.sh` (invokes `group_findings.py` for aggregation).
**Row cardinality:** one row per `(namespace, parent_type, parent_name, repository, digest)` — CVEs of that image are aggregated into `CVE_COUNT`, `CVE_LIST`, `CVE_SEVERITY_MAP`, `CVSS_SCORE` (max).
**Encoding:** UTF-8, LF line endings.

## Header (exact string)

```csv
NAMESPACE,PARENT_TYPE,PARENT_NAME,REPOSITORY,DIGEST,TAG,CVE_COUNT,CRITICALITY,CVSS_SCORE,CVE_LIST,CVE_SEVERITY_MAP,PACKAGE_CATEGORY,PACKAGE_LANGUAGE,PACKAGE_NAME,CURRENT_VERSION,FIXED_VERSION,PATCHABLE,REMEDIATION,FIX_STATUS,CVE_AGE_DAYS,IS_IN_EXPLOIT_KIT,HAS_PUBLISHED_EXPLOIT,HAS_VERIFIED_EXPLOIT,LAST_PUSHED_TO_REGISTRY_UTC
```

## Columns (24)

| # | Name | Type | Notes |
|---|---|---|---|
| 1 | `NAMESPACE` | string | OpenShift project name |
| 2 | `PARENT_TYPE` | string | `Deployment` / `StatefulSet` / `DaemonSet` / `Job` / `Pod` (fallback) — derived from `ownerReferences` chain |
| 3 | `PARENT_NAME` | string | Name of the workload controller (or pod name for standalone pods) |
| 4 | `REPOSITORY` | string | Same as `vulnerable_images_report.repository` |
| 5 | `DIGEST` | string | Same as `vulnerable_images_report.digest` |
| 6 | `TAG` | string | Same as `vulnerable_images_report.tag` |
| 7 | `CVE_COUNT` | integer | Number of unique CVEs on this (workload, image) |
| 8 | `CRITICALITY` | string | Worst severity across the CVEs (`Critical`/`High`/…) |
| 9 | `CVSS_SCORE` | number-as-string | Max CVSS across the CVEs |
| 10 | `CVE_LIST` | string | Comma-separated CVE IDs |
| 11 | `CVE_SEVERITY_MAP` | string | `CVE-ID:severity` pairs, comma-separated |
| 12–24 | (rest) | strings | Package + fix + exploit fields carried over from `vulnerable_images_report.csv` (uppercased with underscores) |

## Namespace coverage classification

Every namespace `check_ocp.sh` visits is classified into exactly one of these five states, logged in the run header. Coverage is used to gate whether the downstream report is authoritative.

| Classification | Meaning | Effect on exit code |
|---|---|---|
| `SUCCESS_WITH_PODS` | Pods listed and correlated with the CVE CSV | Contributes to a COMPLETE run |
| `NO_PODS` | Namespace exists but has zero running pods (normal for empty envs) | Contributes to a COMPLETE run |
| `RBAC_ERR` | HTTP 403 from `oc get pods` — service account lacks list-pods | Downgrades run to PARTIAL |
| `OC_ERR` | Non-403 error from `oc` (API down, transient network) | Downgrades run to PARTIAL |
| `PARSE_ERR` | JSON returned but could not be parsed | Downgrades run to PARTIAL |

## Exit codes

- `0` — `COVERAGE: COMPLETE` (all namespaces classified as `SUCCESS_WITH_PODS` or `NO_PODS`).
- `3` — `COVERAGE: PARTIAL` (at least one `RBAC_ERR` / `OC_ERR` / `PARSE_ERR`).

**Rule (frozen behavior):** a report with `COVERAGE: PARTIAL` MUST NOT be distributed as authoritative. Downstream automation must not treat exit `3` as success.

## Excluded namespaces (frozen filter)

Platform-managed namespaces are filtered out to reduce noise:

- `openshift-*`
- `kube-*`
- `default`
- `logging`
- `monitoring`

Any change to this list must be documented here and mirrored in the Python `openshift/client.py` (task P0.6) when it lands.

## Row order (Python producer only)

The bash producer emits rows in `oc get pods` iteration order (unstable across API calls). The Python producer sorts before writing so diffs, tests, and downstream consumers are deterministic:

1. `NAMESPACE` asc
2. `PARENT_TYPE` asc
3. `PARENT_NAME` asc
4. `REPOSITORY` asc
5. `DIGEST` asc

This matches the natural grouping hierarchy (namespace → workload → image). Enforced by `defender_pipeline.openshift.cluster._write_grouped_csv` and covered by `tests/test_defender_pipeline_cluster.py::TestOutputOrdering`.

Order is a **soft contract for the Python producer** — the bash producer may emit rows in any order Kubernetes returns.

## Guardrails

- `tests/test_contracts.py::TestResultadoCruzamentoContract` — header parity between `check_ocp.sh:232` and the canonical spec above.
- `tests/test_check_ocp_integration.py` — coverage classification behavior with mocked `oc`.
- `tests/test_defender_pipeline_cluster.py::TestOutputOrdering` — Python producer emits rows in the sort order above; identical input produces identical output across runs.
