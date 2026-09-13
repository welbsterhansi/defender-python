# Copilot instructions — defender-pipeline

Espelho de `AGENTS.md`. Regras essenciais para sugestões de código.

## Contexto

Pipeline Python que scan Azure Container Registry via Defender for Cloud (Resource Graph + Container Registry SDKs), cruza com workloads OpenShift (kubernetes client), e expande em CSV por CVE.

Sem `subprocess("az", ...)` / `subprocess("oc", ...)` na main path — só SDKs Python.

## Não faça

1. **Não sugerir nomes de cliente.** Placeholders: `contosoregistry`, `contoso/webapp`, `ns-app`, `ns-shared`.
2. **Não alterar header/ordem dos CSVs** definidos em `defender_pipeline/{findings,openshift,reports}/csv_contracts.py`. São contratos frozen (ver `docs/contracts/`).
3. **Não invocar `az`/`oc` via subprocess.** Use `azure-*` SDKs e `kubernetes` client.
4. **Não misturar refactor com feature** no mesmo commit.
5. **Não commitar** `claude.md` / `CLAUDE.md` / `.claude/` — já no `.gitignore`.
6. **Não adicionar mocks em produção** — mocks só em `tests/` com `unittest.mock`.

## Faça

1. **Type hints** em toda função nova.
2. **Testes** com fixtures neutras (`ns-app`, `contoso/webapp`) e mocks de SDK.
3. **Rodar** `pytest -q` + `ruff check .` antes de qualquer commit.
4. **Sort determinístico** ao produzir CSVs — respeitar contratos em `AGENTS.md`.
5. **Exit codes** conforme `AGENTS.md`: 0 sucesso, 1 erro, 2 not-implemented, 3 partial-coverage (CLUSTER).
6. **Logging estruturado** via `logging_setup.setup(log_format=...)`.

## Como sugerir mudanças

- Preferir edição de arquivos existentes vs criar novos.
- Manter comentários só onde o "porquê" não é óbvio.
- Preservar simplicidade — nada de abstrações preventivas.
- Se a mudança afeta contrato, sinalizar `NEEDS APPROVAL` no PR.
