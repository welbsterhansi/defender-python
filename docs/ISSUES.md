# Issue History

Running log of bugs/issues found and fixed on this repo. Keeps the "why"
that commit messages compress away. See also `AGENTS.md` for general agent
rules and `.github/copilot-instructions.md` for Copilot.

---

## ISSUE-001 — Exploit flags collapsed to `false` in `resultado_cruzamento.csv`

- **Status:** fixed on branch `fix/arg-api-version-and-exploit-flags`
- **Reported:** 2026-10-20 by Copilot + client observation
- **Scope:** value semantics only; 24-column CSV contract unchanged

### Summary

`resultado_cruzamento.csv` (grouped output) shows `IS_IN_EXPLOIT_KIT`,
`HAS_PUBLISHED_EXPLOIT`, `HAS_VERIFIED_EXPLOIT` as `false` for images whose
CVEs do have exploits. `expanded.csv` correctly shows `true` for the same
CVEs. Analysts filtering by exploit flags on the cruzamento miss vulnerable
images (false negatives on a risk-prioritisation field).

### Root cause

`defender_pipeline/openshift/_group_findings.py::group_rows` groups rows by
`(NAMESPACE, PARENT_TYPE, PARENT_NAME, repository, digest)` and kept a
single value per group using "last non-empty value wins":

```python
# _group_findings.py (buggy)
for col in CARRIED_FIELDS:
    v = row.get(col, "")
    if v and v not in ("N/A", ""):
        entry[col] = v
```

The string `"false"` is truthy and not in `("N/A", "")`, so a later CVE row
with `"false"` overwrites an earlier `"true"`. Result is order-dependent and
produces false negatives whenever a group mixes CVEs with and without
exploits.

`defender_pipeline/reports/expand.py::_lookup` ignores the grouped columns
and re-looks-up `(repository, digest, cveId)` in the Defender index, so
`expanded.csv` emits the true per-CVE values — hence the divergence between
the two CSVs.

### Fix

Separate `EXPLOIT_FLAG_FIELDS` from `CARRIED_FIELDS`. Exploit flags are
aggregated with boolean-OR semantics: the group value is `"true"` iff any
CVE in the group is `"true"` (case-insensitive compare against the literal
`"true"`; empty / `"N/A"` / anything else contributes nothing).
Header/column order unchanged.

### Known related concern — NOT fixed here (NEEDS APPROVAL)

Same "last non-empty wins" strategy still applies to the other per-CVE /
per-package carried fields: `PACKAGE_NAME`, `CURRENT_VERSION`,
`FIXED_VERSION`, `FIX_STATUS`, `CVE_AGE_DAYS`, `PATCHABLE`,
`LAST_PUSHED_TO_REGISTRY_UTC`, `PACKAGE_CATEGORY`, `PACKAGE_LANGUAGE`.
These are inherently per-CVE and cannot be summarised as a single group
value without losing information. Options (defer to repo owner):

1. Blank them in the grouped CSV.
2. Pick an explicit aggregation per column.
3. Document in `docs/contracts/` that only `expanded.csv` is authoritative
   for per-CVE fields.

### Validation

Unit tests in `tests/test_defender_pipeline_cluster.py::TestExploitFlagAggregation`
cover a group with mixed `true` / `false` CVEs in both orders (neutral
fixtures `ns-app`, `contoso/webapp`): true-then-false, false-then-true,
all-false regression guard, mixed-per-flag independence, and empty-string
treated as false. `pytest` + `ruff` + `pyright` pass clean on the touched
files.

---

## ISSUE-002 — Azure Resource Graph pagination not resilient at scale

- **Status:** fixed on main — P0.1–P0.4 landed via branch
  `fix/arg-pagination-resilience`. P1.1 (checkpoint + resume) and P1.2
  (structured per-batch log) remain as planned follow-up (not blocking).
- **Reported:** 2026-10-21 — client incident: `acr.csv` run with ~12k
  digests returned incomplete rows; a per-image rescan (`fad/financebatch:1.0.9v2`)
  produced 149 lines vs ~1 line previously. Loss was silent.
- **Severity:** HIGH — risk-prioritisation data (exploit flags, CVE lists)
  silently incomplete; impact scales with digest volume and scan duration.

### Root cause

Two independent gaps combined to produce silent data loss:

1. **ARG queries have no `order by`.** `defender_pipeline/azure/queries.py`
   (`build_enumerate_digests_query`, `build_batched_assessments_query`,
   `build_batched_cvedetails_query`) finish with `distinct` / `summarize`
   but never emit a total order. Microsoft documents that skip-token
   pagination without a total ordering may **duplicate or omit records**
   across pages ([Resource Graph — Query pagination][arg-page]). Probability
   grows with page count — the client's 12k-digest scan traversed many
   pages.

2. **Completeness signals from the SDK are discarded.** The ARG
   `QueryResponse` carries `total_records`, `count` (rows in *this* page)
   and `result_truncated` alongside `data`/`skip_token`. The current
   wrapper (`defender_pipeline/azure/resource_graph.py:88-93`) returns
   only `data` + `skip_token`. `iter_pages` drains until `skip_token` is
   empty and never checks whether the collected row count matches
   `total_records` — so a page that was skipped (cause 1) or truncated
   is lost without any alarm. The client only noticed by comparing two
   runs.

[arg-page]: https://learn.microsoft.com/azure/governance/resource-graph/concepts/work-with-data#paging-results

### Why just `order by` is not enough

Adding `order by` fixes the ordering determinism (cause 1) and resolves
the observed incident. It does **not** address:

- **Snapshot consistency across pages.** ARG does not guarantee that
  pages come from a single point in time. A 2.4h scan can see
  assessments change between pages. This is an ARG service limit, not
  a code bug — but a completeness invariant lets us detect its effect.
- **Silent loss from any future cause.** Any new source of per-page
  skip (SDK bug, transient 5xx not retried, custom top value hitting an
  edge case) stays undetected without completeness validation.
- **Multi-hour scan loss on terminal failure.** A `BatchExhausted` or
  completeness failure late in a scan currently discards everything
  collected so far — the operator rediscovers the problem after hours
  of wall time.

### Remediation plan (aligned with team direction)

**P0 — incident fix + close-the-loop detection** (critical; the two
together are the acceptance criterion):

- **P0.1 (task #6)** — add `order by` after `distinct`/`summarize` on all
  three queries. The ordering key must make rows unique (total order);
  since each query ends with `distinct` over all projected columns, any
  stable ordering over those columns is total.
- **P0.2 (task #7)** — preserve `total_records`, `count`,
  `result_truncated` in the dict returned by `run_query`.
- **P0.3 (task #8)** — in `iter_pages`: accumulate `count` across pages,
  compare against `total_records` from the first response, detect
  `result_truncated=true` without a `skip_token`. On divergence, re-run
  the *entire* batch drain (bounded retries, default 3). If divergence
  persists, raise a terminal `CompletenessError` — **do not emit a CSV**.
  Fail closed.
- **P0.4 (task #9)** — synthetic multipage tests (>1000 rows) covering:
  happy path with `total_records` matching; duplicate rows across
  skip-tokens; missing `skip_token` with `result_truncated=true`;
  `total_records` divergent from received rows; mutation between
  pages; two runs of the same scan compared by unique key (not count).

**P1 — reduce operational impact** (not required for the fix, but
required to be production-safe at scale):

- **P1.1 (task #10)** — atomic per-batch checkpoint
  (`.checkpoint.json` written via write-rename). `--resume` re-reads
  the checkpoint and skips completed batches. CSV is written **only**
  when the full scan succeeds — never partial.
- **P1.2 (task #11)** — per-batch structured log line:
  `batch_id`, `items_in`, `rows_expected` (from `total_records`),
  `rows_received`, `duplicates_dropped`, `pages_consumed`, `attempts`,
  `result_truncated_flag`, `elapsed_ms`. Format designed to grep/parse
  during client triage.

### Acceptance criterion (from team direction)

A fix is accepted iff **all** of:

1. **Total order** — `order by` on all paginated queries over keys that
   make rows unique.
2. **Completeness invariant** — `rows_received == total_records` at end
   of drain; no `result_truncated=true` with empty `skip_token`.
3. **Integral batch retry** — on divergence, repeat the whole batch
   (not just the failing page), bounded.
4. **Fail closed** — persistent divergence raises terminal; no CSV
   emitted; non-zero exit code.
5. **Multipage test in scale** — synthetic fixtures >1000 rows covering
   adversarial scenarios (dup/missing-token/truncated/mutant);
   comparison-by-key between two runs of the same scope.

### Why these alternatives were rejected

- **Pre-count via `summarize count()`** — adds a separate query, opens a
  drift window between count and read. `total_records` from the actual
  response is strictly better (same transaction, zero extra query).
- **`--allow-partial`** — would emit an incomplete CSV with a warning.
  "Fail open" is worse than the current behavior for a security tool
  (risk-prioritisation data must be complete or absent). Replaced by
  P1.1 (checkpoint + resume), which preserves work without publishing
  partial reports.

### Open — needs separate investigation (NOT part of this issue)

- **K8s list pagination (`list_namespace` / `list_namespaced_pod`).**
  Earlier analysis flagged this as HIGH severity on the assumption that
  the apiserver silently chunks at 500 items. The code currently does
  not pass `_continue=` / `limit=`, but actual truncation behavior
  depends on apiserver flags
  (`--default-watch-cache-size`, chunk-size) and client defaults. No
  loss has been observed in the field. Separate investigation ticket
  before deciding.
- **Snapshot filter via `properties.timeGenerated`.** Would create a
  virtual snapshot for long-running scans. Depends on whether Defender
  exposes a usable timestamp on `securityresources` assessments. Spike
  before implementing.

### Related non-fixes to review

- **ACR tag resolution** (`defender_pipeline/azure/acr.py:52-71`) has
  no retry — a transient 429/503 silently converts all digests in that
  repo to `TAG=N/A`. Does **not** explain the observed CVE loss (that
  is pagination), but is an orthogonal reliability gap. Track
  separately once ISSUE-002 lands.
- **Request timeout** (`defender_pipeline/config.py:25` =
  `request_timeout_s=60`) is defined but not forwarded to the SDK
  `self._client.resources(request)` call. Same — orthogonal, track
  separately.

### Suite baseline — env-missing failures vs regression (as of P0.4)

`pytest` on this branch reports **28 failures / 116 passes**. All 28
failures are pre-existing *environment* gaps, not regressions. Audited
by failing-import root cause:

| Count | Group | Root cause | Resolution |
|---|---|---|---|
| 16 | A | `from datetime import UTC` (Python 3.11+ only). Local dev runs Python 3.10, which does not export `datetime.UTC`. Affected: `TestEnrichMerge` (11), `TestScanOrchestrator` (2), `TestCliScan` (2), `TestCLI::test_expand_subcommand_runs_end_to_end` (1) — all transitively import `defender_pipeline/findings/enrich.py:18`. | CI runs Python ≥3.11 per `pyproject.toml`. Expected green on CI. |
| 12 | B | `No module named 'kubernetes'`. Local dev env is missing the OCP client SDK. Affected: `TestCliCluster` (2), `TestNamespaceClassification` (6), `TestOutputOrdering` (2), `TestRunClusterEndToEnd` (2). | CI installs `kubernetes` from `pyproject.toml` extras. Expected green on CI. |

**Zero regressions introduced by P0.1–P0.4.** Verified by
`git stash && pytest` baseline before every commit (same 28 failures
pre and post). The pagination-resilience changes do not import either
`datetime.UTC` nor `kubernetes`.

Local reproduction: install extras (`pip install -e .[pipeline]` plus
the kubernetes client) and run Python ≥ 3.11 — all 28 are expected to
pass. CI is the authoritative environment.

