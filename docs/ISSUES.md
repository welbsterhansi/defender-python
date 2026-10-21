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
