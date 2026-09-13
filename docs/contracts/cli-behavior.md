# CLI behavior contracts

Semantic contracts for the CLI flags of `defender.sh` (and the equivalents the future Python `defender_pipeline` CLI will expose).

## `defender.sh` flags

### Scope selection (mutually exclusive)

| Flag | Semantics | Frozen behavior |
|---|---|---|
| `--acr-name <name>` | Required. Target ACR. | Validated via `az acr show` before scan. |
| `--repository <substring>` | Broad substring filter. `contains` semantics. | `app` matches `app`, `app-backend`, `myapp`. **Single repo only.** |
| `--repositories <a,b,c>` | Controlled EXACT list, comma-separated. | Each entry must exist exactly in the ACR. Empty entries (`,,`), duplicates, or missing repos abort BEFORE the scan. `app` does NOT capture `app-backend`. |
| `--scan-image <ref>` | Scan a specific `repo`, `repo:tag`, or `repo@sha256:digest`. | When a digest is provided, Phase 0 enumerate is bypassed (we already know the pair). |

**Mutual exclusion** (frozen, validated at CLI parse time — exits 1 with a clear message):
- `--repository` + `--repositories` → error
- `--repository` + `--scan-image` → error
- `--repositories` + `--scan-image` → error
- `--skip-tags` + `--scan-image` → error (tag→digest resolution requires the tag lookup)

### CVSS band filter

| Flag | Default | Semantics |
|---|---|---|
| `--min-score <N>` | `9` | KQL `where cvssScore >= N` |
| `--max-score <N>` | `10` | KQL `where cvssScore <= N` |

Applied **after** enrichment (so filtered scores reflect the real cvedetails value, not the inline fallback).

### Action mode (frozen)

| Flag | Effect | Path used |
|---|---|---|
| (default) | Report-only CSV, no side effects | **P2 batched path** |
| `--block-images` | Sets `readEnabled=false` on matching ACR manifests | Legacy per-digest path (narrow-scope by design) |
| `--unblock` | Reverses `--block-images` for the same query | Legacy per-digest path |
| `--unblock-all` | Unblocks every blocked manifest in the ACR / repository | Legacy per-digest path |
| `--image <ref>` | Unblock a single `repo@sha256:...` | Legacy per-digest path |
| `--list-blocked` | Enumerates currently blocked manifests | Legacy per-digest path |

**Safety (frozen):** `--block-images` / `--unblock*` require explicit confirmation unless `--auto-approve` is set. `--auto-approve` and `--dry-run` are both frozen semantics.

### Performance flags

| Flag | Semantics | Frozen behavior |
|---|---|---|
| `--skip-tags` | Skips Phase 1 (tag_resolve) entirely. | Zero `az acr repository show-tags` calls. Every CSV row emits `tag="N/A"`. Log line `"tag_resolve DISABLED via --skip-tags"` MUST appear in the audit trail. |
| `--debug` | Prints the enumerate + per-digest scan KQL. | For diagnostics only. |

## Log format (frozen for dashboards/parsers)

`defender.sh` emits one INFO line per phase (see `docs/mdvm-two-phase-benchmark.md`):

```
INFO  start acr=<name> mode=<mode> score_range=<min>..<max>
INFO  tag_resolve DISABLED via --skip-tags        # only when --skip-tags
INFO  enumerate: found <N> unique pairs in <M> page(s) time_ms=<T>
INFO  tag_resolve: start unique_repos=<N>          # only when NOT --skip-tags
INFO  tag_resolve: end api_calls=<A> cached_pairs=<B> time_ms=<T>
INFO  phase2a assessments_batched: start batch_size=<S> pairs=<N>
INFO  phase2a assessments_batched: end batches=<B> rows=<R> time_ms=<T>
INFO  phase2b extract_cves: unique_cves=<N> time_ms=<T>
INFO  phase2c cvedetails_batched: start batch_size=<S>
INFO  phase2c cvedetails_batched: end batches=<B> rows=<R> time_ms=<T>
INFO  phase2d merge: enrich_cvedetails rows_read=<X> rows_emitted=<Y> rows_enriched=<Z> cvedetails_keys=<K> time_ms=<T>
INFO  end total_processed=<N> digests=<D> pages=<P> report_file=<path>
```

Any change to field names or order requires updating `tests/test_defender_batched_integration.py::TestBatchedPhaseLogs` and any downstream log parsers.

## Retry / backoff (frozen)

Every ARG call goes through `run_arg_rest_query`:
- 3 attempts total.
- Backoff between attempts: `[2, 5]` seconds (no sleep after last attempt).
- Failure counted: `az rest` non-zero exit OR response not valid JSON OR missing `.data` field.
- After exhausting retries, `_scan_batch_recursive` splits the batch in half and retries the halves recursively.
- Never falls silently to 1-by-1: every split logs a WARN; a single-item failure aborts with an ERROR.

## OpenShift coverage classification (frozen)

Per `check_ocp.sh`, every namespace visited is classified into one of five states. Any change requires approval + downstream doc updates.

| Classification | Trigger |
|---|---|
| `SUCCESS_WITH_PODS` | `oc get pods` returned rows AND correlation with the CVE CSV succeeded |
| `NO_PODS` | Namespace exists but no running pods |
| `RBAC_ERR` | HTTP 403 from `oc get pods` |
| `OC_ERR` | Non-403 error (API down, network) |
| `PARSE_ERR` | Response was received but JSON could not be parsed |

**Rule:** report with `COVERAGE: PARTIAL` (any `*_ERR`) is NOT authoritative. Exit code:
- `0` if COMPLETE
- `3` if PARTIAL

Downstream automation must treat `3` as failure.

## Excluded namespaces (frozen filter)

`check_ocp.sh` filters out these platform-managed namespaces:
- `openshift-*`
- `kube-*`
- `default`
- `logging`
- `monitoring`
