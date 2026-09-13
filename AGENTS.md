# AGENTS.md — defender-pipeline

Espelho técnico das regras deste repo para agentes de IA (Copilot / Claude / Cursor / Aider). O `.github/copilot-instructions.md` carrega a versão auto-carregada pelo Copilot.

---

## O que este repo faz

Pipeline Python que:
1. **scan** — consulta Azure Resource Graph + Defender for Cloud, emite `vulnerable_images_report.csv` (19 cols).
2. **cluster** — cruza com workloads OpenShift via `kubernetes` client, emite `resultado_cruzamento.csv` (24 cols).
3. **expand** — explode CSVs agrupados em uma linha por CVE, emite `expanded.csv` (22 cols).

Todas as operações usam SDKs Python diretamente. Zero `az`/`oc` subprocess na main path.

---

## Regras invioláveis

1. **Contratos CSV são congelados.** Header, ordem de colunas e semântica estão em `docs/contracts/`. Alteração exige aprovação explícita e migração dos consumers.
2. **Sem nomes de cliente.** Placeholders neutros no padrão Microsoft: `contosoregistry`, `contoso/webapp`, `ns-app`, `ns-shared`. Grep `-iE 'bdso|novobanco|rhsso|redhat-sso|prd-fad|prd-shared|telefonica'` deve retornar 0 matches.
3. **Nunca commitar `claude.md` / `CLAUDE.md` / `.claude/`.** Já no `.gitignore`.
4. **Rodar `pytest -q` + `ruff check .`** antes de commitar. Zero regressões.
5. **Sem chamadas reais Azure/OCP em testes.** Sempre mockar SDKs via `unittest.mock`.
6. **Não invocar produção sem aprovação.** Comandos que tocam Azure/cluster real vão pro `client-probe.sh` com output enxuto.

---

## Arquitetura de módulos

```
defender_pipeline/
├── cli.py                  # argparse dispatcher
├── config.py               # from_env() com concurrency/timeouts
├── logging_setup.py        # structured logs (text|json)
├── azure/
│   ├── auth.py             # DefaultAzureCredential chain
│   ├── resource_graph.py   # ARG queries batch + skip-token
│   ├── acr.py              # ContainerRegistryClient wrappers
│   └── queries.py          # KQL frozen strings
├── findings/
│   ├── scan.py             # orchestrator scan
│   ├── enrich.py           # merge assessments + cvedetails, sort final
│   ├── models.py           # dataclasses Finding, Assessment, etc.
│   └── csv_contracts.py    # 19-col header contract
├── openshift/
│   ├── client.py           # kube config loader
│   ├── cluster.py          # orchestrator cluster
│   ├── correlate.py        # image → workload matching
│   ├── coverage.py         # partial-coverage exit code contract
│   ├── csv_contracts.py    # 24-col header contract
│   └── _group_findings.py  # vendored grouper (uppercase 24-col output)
├── reports/
│   ├── expand.py           # 3-level lookup ladder (full/repo+cve/prefix)
│   ├── csv_contracts.py    # 22-col header contract
│   └── html.py             # (P0.7b — não implementado ainda)
└── utils/
    ├── batching.py         # divide-and-conquer helpers
    ├── concurrency.py      # ThreadPoolExecutor wrappers
    ├── csvio.py            # bash-compat quoting (QUOTE_ALL + " → ')
    └── retry.py            # tenacity policies
```

---

## Contratos de sort (regressões silenciosas se quebrar)

**scan (`findings/enrich.py::merge`):**
`(-cvssScore, repository, digest, cveId, packageName)` — replaces the KQL `order by cvssScore desc` we lost after batching.

**cluster (`openshift/cluster.py`):**
`(NAMESPACE, PARENT_TYPE, PARENT_NAME, REPOSITORY, DIGEST)` — Kubernetes list order isn't stable across API calls.

**expand:** preserves cluster input order + alphabetical CVE order within each group.

Guardados em `tests/test_defender_pipeline_scan.py::TestEnrichMerge::test_deterministic_sort_order` (+ `test_sort_is_stable_across_calls`).

---

## Exit codes (contrato público)

- `0` — sucesso
- `1` — erro (auth, network, schema quebrado)
- `2` — subcomando não implementado
- `3` — **CLUSTER apenas**: partial coverage (nem toda imagem vulnerável está no cluster)

---

## Fluxo de trabalho

1. Criar task antes de código. Prioridade e testes primeiro.
2. Preferir editar arquivos existentes vs criar novos.
3. Comentários só onde o "porquê" não é óbvio — não descrever o "o quê".
4. Commit atômico com mensagem clara. `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>` quando gerado com Claude.
5. Não pushar sem OK explícito.

---

## Este repo tem um fallback bash

O pipeline bash original (`defender.sh`, `check_ocp.sh`, `expandcsv.py`, `report.py`) vive em outro repo (`defender`), validado em produção e mantido como baseline enquanto a versão Python é validada em paralelo. Byte-equivalence testada uma vez; guardas de contrato preservam paridade.
