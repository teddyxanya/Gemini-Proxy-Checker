#!/usr/bin/env bash
set -euo pipefail

WORKDIR="/opt/gemini-proxy-checker"
STATE_FILE="${WORKDIR}/checker_state.json"
cd "${WORKDIR}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# Проверяем, есть ли рабочие ноды
if [ ! -f "${STATE_FILE}" ]; then
    log "State file not found. Skipping quick check."
    exit 0
fi

# Извлекаем названия рабочих нод (web)
WORK_NODES=$(python3 -c "import json, sys; d = json.load(open('${STATE_FILE}')); print(','.join(d.get('web', [])))" 2>/dev/null || echo "")

if [ -z "${WORK_NODES}" ]; then
    log "No active Gemini nodes in state. Skipping quick check."
    exit 0
fi

log "Running QUICK check for active nodes: ${WORK_NODES}"

export QUICK_CHECK=1
export QUICK_NODES="${WORK_NODES}"

if [ -f ".env" ]; then
    set -a
    source .env
    set +a
fi

PYTHONUNBUFFERED=1 "${WORKDIR}/venv/bin/python3" -u "${WORKDIR}/checker.py"
EXIT_CODE=$?

if [ ${EXIT_CODE} -eq 0 ]; then
    log "Quick check OK. All nodes still working."
else
    log "Quick check FAILED (some nodes dropped). Triggering FULL check via run.sh..."
    bash "${WORKDIR}/run.sh"
fi
