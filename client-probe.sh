#!/usr/bin/env bash
# client-probe.sh — valida a pipeline Python end-to-end no cliente.
#
# Roda APENAS `python -m defender_pipeline` (scan → cluster → expand).
# Nao invoca defender.sh/check_ocp.sh — a comparacao bash x python fica
# nos testes locais (tests/test_defender_pipeline_*.py).
#
# Uso:
#     git pull origin main
#     python3 -m venv .venv && source .venv/bin/activate
#     pip install -e '.[pipeline]'   # aspas obrigatorias — bash expande []
#     bash client-probe.sh
#
# Pre-req: az login (scan) + oc login (cluster) + extra [pipeline] instalado
# (traz azure-identity, azure-mgmt-resourcegraph, azure-containerregistry,
# kubernetes, tenacity — sem esses o scan falha com ImportError).
#
# Overrides via env (SEMPRE passar os reais — os defaults sao placeholders):
#     ACR=<name>           default contosoregistry
#     REPO=<substring>     default contoso/webapp  (scope pequeno)
#     MINSCORE=<float>     default 7

set +e

ACR="${ACR:-contosoregistry}"
REPO="${REPO:-contoso/webapp}"
MINSCORE="${MINSCORE:-7}"

WORK=$(mktemp -d) || { echo "erro: mktemp"; exit 1; }
trap 'rm -rf "$WORK"' EXIT

SCAN_CSV="$WORK/scan.csv"
CLUSTER_CSV="$WORK/cluster.csv"
EXPAND_CSV="$WORK/expand.csv"

# Contratos congelados
COLS_SCAN=19
COLS_CLUSTER=24
COLS_EXPAND=22

check_stage() {
    local label="$1" csv="$2" rc="$3" cols_expected="$4" log="$5"
    local rows="-" cols="-" status="fail"
    if [[ -f "$csv" ]]; then
        rows=$(( $(wc -l < "$csv" | tr -d ' ') - 1 ))
        cols=$(head -n1 "$csv" | awk -F',' '{print NF}')
        if [[ "$rc" -eq 0 && "$cols" -eq "$cols_expected" && "$rows" -ge 0 ]]; then
            status="ok"
        fi
    fi
    printf "%-8s rows=%-6s cols=%-3s rc=%-3s %s\n" \
        "$label" "$rows" "$cols" "$rc" "$status"
    if [[ "$status" != "ok" && -s "$log" ]]; then
        echo "         ↳ $(tail -n1 "$log" | cut -c1-120)"
    fi
    [[ "$status" == "ok" ]]
}

# ── 1. SCAN ──────────────────────────────────────────────────────────────
python3 -m defender_pipeline scan --acr-name "$ACR" --repository "$REPO" \
    --min-score "$MINSCORE" --skip-tags \
    --output "$SCAN_CSV" >/dev/null 2>"$WORK/scan.err"
SCAN_RC=$?

# ── 2. CLUSTER ───────────────────────────────────────────────────────────
python3 -m defender_pipeline cluster \
    --vulnerabilities "$SCAN_CSV" \
    --output "$CLUSTER_CSV" >/dev/null 2>"$WORK/cluster.err"
CL_RC=$?

# ── 3. EXPAND ────────────────────────────────────────────────────────────
python3 -m defender_pipeline expand \
    --cruzamento "$CLUSTER_CSV" \
    --vulnerabilities "$SCAN_CSV" \
    --output "$EXPAND_CSV" >/dev/null 2>"$WORK/expand.err"
EX_RC=$?

# ── 4. Veredicto ─────────────────────────────────────────────────────────
OK=0
check_stage "SCAN"    "$SCAN_CSV"    "$SCAN_RC" "$COLS_SCAN"    "$WORK/scan.err"    && OK=$((OK+1))
check_stage "CLUSTER" "$CLUSTER_CSV" "$CL_RC"   "$COLS_CLUSTER" "$WORK/cluster.err" && OK=$((OK+1))
check_stage "EXPAND"  "$EXPAND_CSV"  "$EX_RC"   "$COLS_EXPAND"  "$WORK/expand.err"  && OK=$((OK+1))
printf "RESULT   %d/3 stages ok\n" "$OK"

[[ "$OK" -eq 3 ]]
