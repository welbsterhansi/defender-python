# defender-pipeline

Python API-first pipeline: scan an **Azure Container Registry (ACR)** for vulnerabilities via **Microsoft Defender for Cloud**, cross-reference the results with **workloads running in OpenShift**, and expand into per-CVE rows for reporting.

Uses Azure SDKs (`azure-mgmt-resourcegraph`, `azure-containerregistry`) and the `kubernetes` Python client directly — no `az` / `oc` subprocess in the main path.

> **AI assistants:**
> - GitHub Copilot reads [`.github/copilot-instructions.md`](./.github/copilot-instructions.md) automatically.
> - Claude Code / Cursor / Aider read [`AGENTS.md`](./AGENTS.md).
>
> Both files carry the same rules. Update both when architecture changes.

---

## Do zero ao primeiro run (junior-friendly)

Passo a passo pra rodar numa máquina limpa (Linux/WSL, Python 3.11+).

```bash
# 1. Clone
git clone <URL_DO_REPO> defender-python && cd defender-python

# 2. Virtualenv Python
python3 -m venv .venv
source .venv/bin/activate

# 3. Instala dependências (Azure SDKs + kubernetes client + tenacity)
pip install -e .

# 4. Login nos serviços
az login          # Azure — pra scan (ARG + ACR)
oc login <URL>    # OpenShift — pra cluster

# 5. Roda o probe end-to-end (scan → cluster → expand)
ACR=<seu-acr> REPO=<seu-repo> bash client-probe.sh
```

Output esperado (4 linhas):

```
SCAN     rows=NNN  cols=19  rc=0   ok
CLUSTER  rows=NNN  cols=24  rc=0   ok
EXPAND   rows=NNN  cols=22  rc=0   ok
RESULT   3/3 stages ok
```

`rc=3` no CLUSTER é normal (contrato "partial coverage" — nem toda imagem vulnerável está rodando no cluster).

Se algum estágio falhar, aparece uma 5ª linha com o final do stderr. Colar no chat/issue.

---

## CLI

```bash
python -m defender_pipeline scan     --acr-name <ACR> --min-score 7 --max-score 10 --output scan.csv
python -m defender_pipeline cluster  --vulnerabilities scan.csv --output cluster.csv
python -m defender_pipeline expand   --cruzamento cluster.csv --vulnerabilities scan.csv --output expand.csv
```

Subcomando `all` orquestra os 3 estágios; `diff` compara dois CSVs. Veja `python -m defender_pipeline --help`.

### Overrides via env (no `client-probe.sh`)

- `ACR=<name>` — obrigatório na prática (default é placeholder `contosoregistry`)
- `REPO=<substring>` — filtro `contains` do repo
- `MINSCORE=<float>` — default 7

---

## Contratos CSV congelados

Ver [`docs/contracts/`](./docs/contracts/):

- `vulnerable_images_report.csv` — 19 colunas, output do `scan`
- `resultado_cruzamento.csv` — 24 colunas, output do `cluster`
- `expanded.csv` — 22 colunas, output do `expand`

Header, ordem e semântica **não mudam** sem aprovação explícita.

---

## Arquitetura

Ver [`docs/python-architecture.md`](./docs/python-architecture.md) — decisões de SDK, mapeamento de operações Azure/K8s → módulos, contrato de logging, tratamento de retry.

---

## Testes

```bash
pip install -e '.[dev]'
pytest -q
```

100 testes; sem chamadas reais Azure/OCP (Kubernetes API + Azure SDKs mockados via `unittest.mock`).

---

## Contribuindo

- Não colocar nomes de cliente em código/docs/comentários — usar placeholders neutros (`contosoregistry`, `contoso/webapp`, `ns-app`).
- Não alterar KQL ou schema dos CSVs sem aprovação — contratos frozen.
- Rodar `pytest -q` + `ruff check .` antes de commit.
