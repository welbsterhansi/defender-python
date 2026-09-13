# `defender_pipeline` — Python API-first architecture (P0.3 design)

**Status:** design (no code yet).
**Blocks:** implementation tasks P0.4 (skeleton) → P0.5 (scan) → P0.6 (openshift) → P0.7 (expand/report).
**Baseline:** the current Bash + Python pipeline (`defender.sh`, `enrich_cvedetails.py`, `check_ocp.sh`, `expandcsv.py`, `report.py`) stays untouched throughout the migration. See `docs/contracts/` for the frozen artifacts the new implementation must preserve.

---

## 1. Guiding principles

### 1.1. API-first, not CLI wrapper

The whole point of the migration is to eliminate `subprocess.run(["az", ...])` / `subprocess.run(["oc", ...])` from the main path. Every primary operation uses a Python SDK that speaks HTTP/gRPC directly to the underlying service.

| Rejected pattern | Chosen pattern |
|---|---|
| `subprocess.run(["az", "rest", "--url", ...])` | `ResourceGraphClient.resources(QueryRequest(...))` |
| `subprocess.run(["az", "acr", "repository", "show-tags", ...])` | `ContainerRegistryClient.list_manifests(...)` |
| `subprocess.run(["oc", "get", "pods", "-n", ns, "-o", "json"])` | `kubernetes.client.CoreV1Api().list_namespaced_pod(namespace=ns)` |
| `jq` + shell parsing | native Python dict/dataclass |
| `csv_field()` bash regex | `csv.writer(..., quoting=QUOTE_ALL)` (with adapter for internal `"` → `'` to match bash) |

### 1.2. `subprocess` is only allowed as documented fallback

Two specific cases where we may keep or add a controlled `subprocess`:
1. **Local kubeconfig discovery on unusual setups** (`oc whoami --show-token` when `KUBECONFIG` env is not set and there's no in-cluster context). Log a WARN documenting the reason.
2. **One-off admin operations** (block/unblock modes today do PATCH ops via `az acr repository update` — the SDK supports this natively via `ContainerRegistryClient.update_manifest_properties`, so we prefer SDK; if a specific op is not covered by the SDK, subprocess is acceptable with explicit justification in the code comment).

**Never in the main scan/xref/report path.**

### 1.3. Preserve contracts, not implementation

Everything under `docs/contracts/` is the enforceable target. The Python path must:
- Emit `vulnerable_images_report.csv` (19 cols) **byte-identical** to the bash producer for the same input.
- Emit `resultado_cruzamento.csv` (24 cols) with the same coverage classification exit codes.
- Emit `expanded.csv` (22 cols) via the same 3-level lookup ladder.
- Emit `vulnerability_report.html` semantically equivalent (tabs, KPIs, chips, `_image_ref`).

`tests/test_contracts.py` from P0.2 must pass against the Python outputs.

---

## 2. SDK / library decisions

### 2.1. Azure

| Purpose | Library | Version pin | Rationale |
|---|---|---|---|
| Authentication | `azure-identity` | `>=1.15,<2.0` | Standard credential chain. `DefaultAzureCredential` covers all deployment scenarios (dev laptop with `az login`, service principal in CI, managed identity in prod) — no code branches for auth. |
| Resource Graph queries | `azure-mgmt-resourcegraph` | `>=8.0,<9.0` | Official SDK. Wraps `POST /providers/Microsoft.ResourceGraph/resources` with api-version 2022-10-01 default (matches what the Bash P2 code learned to use — see `erros.md`). Type-safe `QueryRequest`/`QueryResponse` instead of manual JSON body building. |
| Container Registry | `azure-containerregistry` | `>=1.2,<2.0` | Data-plane SDK. `ContainerRegistryClient.list_manifests(repository)` gives us digest/tag pairs — replaces the current `az acr repository show-tags --detail --top 5000` path. |
| HTTP pipeline / retry | `azure-core` (transitive) | pinned by above | Built-in `RetryPolicy` with exponential backoff. Configurable per-call. Handles 429 / 5xx / connection errors uniformly. |

**Not used:** `azure-cli-core` (that would be back to being a CLI wrapper).

### 2.2. Kubernetes / OpenShift

| Purpose | Library | Version pin | Rationale |
|---|---|---|---|
| Cluster API | `kubernetes` | `>=29.0,<32.0` | Official Python client, auto-generated from OpenAPI. Covers everything we need: namespaces, pods, owner references. `kubernetes.client.ApiException` gives clean status-code handling for RBAC classification. |
| Kubeconfig loading | `kubernetes.config` (part of `kubernetes`) | — | `load_kube_config()` (dev) + `load_incluster_config()` (in-cluster) with `try/except` for the local-vs-cluster switch. |

**Considered but rejected:**
- `openshift` (openshift/python-client): wraps `kubernetes` but adds OpenShift-specific resources. We don't use OpenShift-specific CRDs today — pods and namespaces are enough. Skipping the extra dependency keeps the wheel small.

### 2.3. General

| Purpose | Library | Version pin | Rationale |
|---|---|---|---|
| CLI framework | `argparse` (stdlib) | — | No `click`/`typer`. Argparse is enough for the ~6 subcommands. Stdlib = one less dep. |
| Structured logging | `logging` (stdlib) + JSON formatter (in-house, ~30 lines) | — | Match today's audit-trail lines. No `structlog` — extra dep for a formatter is overkill. |
| Data classes / models | `dataclasses` (stdlib) + `typing` | — | No `pydantic` in the hot path. We don't have external API contracts to validate — internal typing is enough. If schema validation of CSV rows becomes valuable later, revisit. |
| Retry beyond SDK built-in | `tenacity` | `>=8.2,<10.0` | For the batch-split-on-failure pattern that the Azure SDK's built-in retry doesn't understand (the SDK retries the SAME call; we want to split the batch and retry two smaller ones). Decorator-based, testable. |
| CSV writing | `csv` (stdlib) | — | Custom `csv_field()`/`csv_write_row()` adapter to match the bash escaping (internal `"` → `'`) rather than `csv.writer`'s standard doubling. This is already done in `enrich_cvedetails.py` — port as-is. |
| HTML generation | `jinja2` | `>=3.1,<4.0` | If `report.py` is ported (P0.7). Alternative: keep report.py in Python but call it from the new CLI. Decision deferred to P0.7. |

### 2.4. Dev / test only

| Purpose | Library |
|---|---|
| Test runner | `pytest` |
| Async test support | `pytest-asyncio` (only if we go async) |
| Mocks | `unittest.mock` (stdlib) — SDKs are mockable at the client class level |
| Linting | `ruff` |
| Type checking | `pyright` |

**Total new runtime deps:** 5 (`azure-identity`, `azure-mgmt-resourcegraph`, `azure-containerregistry`, `kubernetes`, `tenacity`). Optional 6th (`jinja2`) if HTML is ported.

---

## 3. Authentication plan

### 3.1. Azure

Single credential object: `DefaultAzureCredential()` from `azure-identity`. The credential chain tries in order:

1. Environment variables (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`) — CI/CD path.
2. Managed identity — in-cluster / VM path.
3. Azure CLI (`az login` cache) — developer laptop path (what the client uses today).
4. Interactive browser — last resort (disabled in headless environments).

Same credential passed to `ResourceGraphClient` and `ContainerRegistryClient`. No code branches for auth.

**Prerequisite (documented in the CLI `--help`):** the identity needs **Security Reader at tenant scope** (validated in P2 discovery — see `erros.md`) so `microsoft.security/cvedetails` enrichment is visible.

### 3.2. Kubernetes

`kubernetes.config` has two entry points; try in order:
1. `load_incluster_config()` — if `KUBERNETES_SERVICE_HOST` env var is set.
2. `load_kube_config()` — reads `~/.kube/config` (or `KUBECONFIG` env). This is what dev laptops use with `oc login`.

If both fail, exit 1 with a message telling the operator to `oc login` or set `KUBECONFIG`.

---

## 4. Retry / backoff / timeouts

### 4.1. Per-request retry (SDK built-in)

Both `ResourceGraphClient` and `ContainerRegistryClient` use `azure-core`'s `RetryPolicy`. Default is 3 retries with exponential backoff on 408/429/500/502/503/504. We accept the default for now; if throttling shows up in prod, tune via:

```python
from azure.core.pipeline.policies import RetryPolicy
retry = RetryPolicy(retry_total=3, retry_backoff_factor=2, retry_backoff_max=30)
client = ResourceGraphClient(credential, retry_policy=retry)
```

Timeout per request: 60 seconds (Azure ARG rarely responds faster than 2s but sometimes hits 30s on complex queries).

### 4.2. Batch-split retry (custom via tenacity)

The SDK retries the SAME call. But our failure mode is `UnexpectedQueryExecutionError` from ARG when the batch is too big — retrying doesn't help; we need to **split**. This is the `_scan_batch_recursive` logic from the bash implementation. In Python:

```python
@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type(TransientARGError),
)
def _run_batch(digests: list[str]) -> list[dict]:
    ...

def scan_batched(digests: list[str], batch_size: int = 50) -> list[dict]:
    try:
        return _run_batch(digests)
    except BatchTooComplex:
        if len(digests) == 1:
            raise
        half = len(digests) // 2
        return scan_batched(digests[:half], batch_size) + scan_batched(digests[half:], batch_size)
```

Same "never fall silently to 1-by-1" invariant as the bash version — every split logs a WARN, single-item failure raises.

### 4.3. Kubernetes retry

`kubernetes.ApiException` with status 5xx or connection errors → retry via `tenacity` (`stop_after_attempt(3)`, `wait_exponential(min=1, max=10)`).
- **`403 Forbidden`** does NOT retry — that's the RBAC classification path (`RBAC_ERR`).
- **`404`** on `list_namespace()` shouldn't happen; if it does, log as `OC_ERR`.

---

## 5. Concurrency model

### 5.1. Decision: **synchronous + `concurrent.futures.ThreadPoolExecutor`**

Not asyncio. Rationale:

- SDK support for async is uneven. `azure-mgmt-resourcegraph` has an `aio` subpackage; `azure-containerregistry` too. But `kubernetes` (official Python client) is sync-only — going async would require `kubernetes-asyncio` (third-party, less mature) or an executor bridge, complicating the code.
- The bottleneck is I/O latency (ARG per-batch ~5s, `list_pods` per namespace ~200ms). Threads are enough — GIL is not the issue.
- Debugging threads is easier than debugging asyncio for a small team.

Implementation:
- `ThreadPoolExecutor(max_workers=8)` — 8 is a safe default; configurable via `--parallelism` flag. Empirical: Azure ARG rate-limits at ~15 QPS per identity, so 8 concurrent workers stays well under.
- Wrap the executor pattern in a small helper (`utils/concurrency.py`) that handles: bounded parallelism, per-task retry propagation, ordered result collection.

### 5.2. Fallback to serial

`--parallelism 1` forces serial execution — used for debugging or when running in constrained environments. Default = 8.

### 5.3. Rate limit awareness

If we start seeing `429` from ARG, apply an `azure-core` `RetryAfter` policy (SDK already handles the `Retry-After` header). If they escalate, drop `--parallelism` first before disabling.

---

## 6. CSV contract preservation

### 6.1. Adapter approach

Every CSV writer in the Python code goes through `defender_pipeline/utils/csvio.py` with two functions:

```python
def csv_field(value: Any) -> str:
    """Match bash `csv_field()` in defender.sh:40-46 EXACTLY:
    wrap in double quotes, internal " → ', collapse \n and \r to space.
    """

def csv_write_row(fout, values: Sequence[Any]) -> None:
    """Match bash `csv_write_row()` in defender.sh:48-55: comma-joined
    csv_field() calls terminated by \n.
    """
```

This is exactly what `enrich_cvedetails.py` already has — porting it here as the single source of truth.

### 6.2. Header definitions as constants

Each CSV contract lives as a module-level constant (already in `enrich_cvedetails.CSV_HEADER_COLUMNS`; will be replicated for `resultado_cruzamento` and `expanded`). `tests/test_contracts.py` reads them and asserts they match `docs/contracts/*.md`.

### 6.3. Diff-clean before cutover

A helper `defender_pipeline diff` subcommand: runs the pipeline in both modes (bash and Python) against the same fixture and reports byte-level differences. Cutover to Python is gated on this diff being clean.

---

## 7. Module structure (proposal)

```
defender_pipeline/
├── __init__.py
├── __main__.py                    # `python3 -m defender_pipeline …`
├── cli.py                         # argparse dispatch, subcommands
├── config.py                      # env vars, defaults, --parallelism
├── logging_setup.py               # audit-trail lines matching cli-behavior.md
│
├── azure/
│   ├── auth.py                    # DefaultAzureCredential factory
│   ├── resource_graph.py          # ARG client + query helpers (batched)
│   ├── acr.py                     # ContainerRegistryClient wrapper (tags)
│   └── queries.py                 # KQL builders (Phase 0 / 2a / 2c)
│
├── findings/
│   ├── models.py                  # @dataclass Finding, Cvedetails, Assessment
│   ├── scan.py                    # main scan orchestrator (phases 0-2d)
│   ├── enrich.py                  # local merge (port of enrich_cvedetails.py)
│   └── csv_contracts.py           # 19-col constants + validation
│
├── openshift/
│   ├── client.py                  # kubernetes.config loader, CoreV1Api
│   ├── correlate.py               # workloads × images cross-ref
│   ├── coverage.py                # 5-state classifier + exit code mapper
│   └── csv_contracts.py           # 24-col constants
│
├── reports/
│   ├── expand.py                  # port of expandcsv.py + 22-col constants
│   └── html.py                    # port of report.py (or wraps it in P0.7)
│
├── utils/
│   ├── batching.py                # split-in-half retry helper
│   ├── retry.py                   # tenacity decorators
│   ├── concurrency.py             # ThreadPoolExecutor wrapper
│   └── csvio.py                   # csv_field / csv_write_row (bash-compat)
│
└── py.typed
```

### 7.1. Public CLI surface

```bash
python3 -m defender_pipeline scan     [--acr NAME] [--min-score N] [--max-score N] [--repository R | --repositories a,b,c] [--skip-tags]
python3 -m defender_pipeline cluster  [--kubeconfig PATH] [--vulnerabilities CSV] [--output CSV]
python3 -m defender_pipeline expand   [--cruzamento CSV] [--vulnerabilities CSV] [--output CSV]
python3 -m defender_pipeline report   [--input CSV] [--output HTML]
python3 -m defender_pipeline all      # scan → cluster → expand → report
python3 -m defender_pipeline diff     # bash vs python output comparison (dev aid)
```

Every subcommand exits `0` on success and non-zero on failure. `cluster` subcommand additionally exits `3` for PARTIAL coverage (matching `check_ocp.sh`).

---

## 8. Testing strategy

### 8.1. Unit tests (per module)

- Mock the SDK client class directly with `unittest.mock.patch`.
- `ResourceGraphClient.resources(...)` → `MagicMock` returning canned `QueryResponse` objects.
- `CoreV1Api.list_namespaced_pod(...)` → `MagicMock` returning `V1PodList`.
- No PATH-mocked binaries needed (that was for `subprocess` — we don't do that anymore).

### 8.2. Contract tests (`tests/test_contracts.py`)

Already exists (P0.2). Extended to read Python-side headers from `defender_pipeline.findings.csv_contracts.VULNERABLE_IMAGES_HEADER_COLUMNS`, `defender_pipeline.openshift.csv_contracts.RESULTADO_CRUZAMENTO_HEADER_COLUMNS`, `defender_pipeline.reports.expand.EXPANDED_HEADER_COLUMNS`. Same canonical list must satisfy every producer.

### 8.3. Integration tests

- Mock the SDK layer, run the full pipeline against synthetic fixtures. `tests/test_defender_pipeline_integration.py` for the Python path (mirroring `tests/test_defender_batched_integration.py` for the bash path).
- Assert same 19/24/22 columns, same field values, same coverage classification.

### 8.4. Diff-runner test

Special test (`tests/test_python_vs_bash_diff.py`, skip by default) that:
- Runs bash pipeline against a small fixture.
- Runs Python pipeline against same fixture (with SDK mocked to return equivalent data).
- Asserts CSV outputs are byte-identical (or, for HTML, structurally equivalent).

Runs in CI as `pytest tests/ -k diff` for opt-in verification.

---

## 9. Migration / parallel operation strategy

### 9.1. Phased rollout

1. **P0.4 skeleton**: package + `--help` works. No production behavior.
2. **P0.5 scan**: report-only scan in Python. `defender.sh` still primary; Python is opt-in via CLI.
3. **P0.6 cluster**: OpenShift cross-ref in Python. Same opt-in.
4. **P0.7 expand + report**: full CLI pipeline in Python.
5. **Validation window** (~2 weeks): both pipelines run in parallel in CI. Diff runner asserts equivalence.
6. **P0.8 cleanup plan**: decision on scripts (delete / wrapper / deprecated-banner) with explicit approval.

### 9.2. `defender.sh` remains untouched

Zero edits to `defender.sh`, `enrich_cvedetails.py`, `check_ocp.sh`, `expandcsv.py`, `report.py` throughout P0.4–P0.7. Confirmed by CI check (`git diff --exit-code` against a whitelist of "may change" files).

### 9.3. Rollback

Since the bash pipeline is untouched, rollback = "don't invoke `python3 -m defender_pipeline …`, invoke `./defender.sh` as before". No code revert needed. That's the whole point of parallel operation.

---

## 10. Open questions (to resolve in P0.4+)

1. **Log format**: audit-trail lines (`INFO enumerate: found ...`) — reproduce EXACTLY or evolve into structured JSON with the human-readable form as one field? Recommendation: keep human-readable lines as-is (dashboards parse them), add structured JSON as opt-in via `--log-format json`.
2. **`report.py` port scope**: port fully to Jinja2 or keep report.py and just call it from the CLI as a subprocess? (Contradicts the "no subprocess" rule, but report.py is a self-contained Python module — it's not the same offense as spawning `az`.) Recommendation: keep report.py as-is in P0.7, call as an `import` not `subprocess`.
3. **HTML byte-identity**: `report.py` output has some non-determinism (order of dict iteration in JS, timestamp of generation). Diff-clean will need to normalize. Recommendation: strip timestamps before diffing; assert on structural markers (KPI counts, tab structure) rather than byte-for-byte.
4. **Distribution**: how do operators install `defender_pipeline`? Options: `pip install -e .`, `pipx install`, or committed venv. Recommendation: `pyproject.toml` with `hatchling`; `pipx install .` for operator workstations, `pip install -e .` for dev.

These will be revisited when each corresponding task starts.

---

## 11. Known behavior — ARG data volatility

Validated empirically at the client during P0.5 (2026-09-12):

- The two Azure Resource Graph tables the pipeline queries
  (``microsoft.security/assessments`` and ``microsoft.security/cvedetails``)
  are **eventually consistent**. Defender re-scans and re-aggregates them in
  background. Two identical queries issued seconds apart routinely return
  slightly different row sets (~1-5% drift observed).
- Consequence: **byte-exact CSV diff between the Bash pipeline and the
  Python pipeline running in separate processes is not a reliable validation
  criterion.** A ~2 minute delta between runs can shift dozens of rows in
  either direction (some CVEs gain enrichment, others lose it → filter
  passes/drops differ).
- Correct validation strategies:
    1. **Contract compliance** — same 19-column schema, same field
       semantics (frozen in ``docs/contracts/``).
    2. **Merger equivalence with controlled input** — see
       ``decision_dump.py``: fetches ARG data ONCE, feeds both
       ``enrich_cvedetails.py`` (bash merger) and
       ``defender_pipeline.findings.enrich.merge`` (python merger),
       compares outputs. Identical output on identical input proves the
       code paths are equivalent even when full-run outputs drift.
    3. **Tuple-set overlap** on the 5-field key
       ``(digest, cveId, packageName, currentVersion, fixedVersion)``.
- Non-strategies (do NOT rely on these):
    - `diff -u bash.csv python.csv` — will always show noise from ARG drift
      and tag-resolution differences.
    - `wc -l` equality between full-run outputs — same reason.

### 11.1 OpenShift live-state volatility (P0.6, 2026-09-12)

The same "eventual state" caveat applies to `check_ocp.sh` vs
`defender_pipeline cluster` back-to-back on a live cluster:

- `oc get pods` (bash) and `list_namespaced_pod` (kubernetes python
  client) are called seconds apart. Pods can start, terminate, restart,
  or move to a different node between the two calls. A pod that exists
  when bash queries but is gone (or newly appeared) when python queries
  produces a tuple present on only one side.
- Validated empirically: full ACR score 9-10 scan → 111 cluster rows on
  both sides, 110 tuples shared on
  `(NAMESPACE, PARENT_TYPE, PARENT_NAME, REPOSITORY, DIGEST)` → **98.2%
  overlap, exactly 1 tuple divergent each side**. Exit code, coverage
  state, and header all matched.
- Threshold used for "strong match": ≤10 divergent tuples per side. Under
  that, we treat any divergence as live-state volatility, not a code
  bug. A systemic bug would produce dozens of consistent divergences.
- If a run shows divergence above threshold, first re-run to check
  whether the delta shrinks — if it does, live-state volatility; if it
  stays high, investigate `_resolve_parent()` / `_extract_image_digests()`
  logic in `openshift/correlate.py`.

## 12. Non-goals (explicit)

- Not building an SDK for third-party consumers. This is an internal pipeline.
- Not supporting Windows (Linux/WSL only, same as current).
- Not adding features beyond parity. Feature work happens after P0.8.
- Not optimizing for further speedup beyond what SDK + threads gives — if the bash P2 is ~1h for the client's ACR, Python target is "≤ same, ideally faster with parallelism". Full asyncio rewrite is out of scope.

---

## Approval to proceed

P0.4 (skeleton) is unblocked once this doc is committed and reviewed. No implementation before then.
