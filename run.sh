#!/usr/bin/env bash
set -euo pipefail

WORKDIR="/opt/gemini-proxy-checker"
cd "${WORKDIR}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

log "=========================================================="
log "Starting Gemini Proxy Checker & e0f.cx Sync Run"
log "=========================================================="

if [ -f ".env" ]; then
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
else
    log "ERROR: .env file not found in ${WORKDIR}!"
    exit 1
fi

GIT_REPO_URL="${GIT_REPO_URL:-}"
BRANCH="${GIT_BRANCH:-main}"

# 1. Handle Git repo initialization and sync
if [ -n "${GIT_REPO_URL}" ] && [[ "${GIT_REPO_URL}" != *"USER/REPO"* ]]; then
    if [ ! -d ".git" ]; then
        log "Initializing git repository in ${WORKDIR}..."
        git init
        git remote add origin "${GIT_REPO_URL}"
        git branch -M "${BRANCH}"
    else
        CURRENT_REMOTE=$(git remote get-url origin 2>/dev/null || true)
        if [ "${CURRENT_REMOTE}" != "${GIT_REPO_URL}" ]; then
            log "Updating git remote URL to ${GIT_REPO_URL}..."
            git remote set-url origin "${GIT_REPO_URL}" 2>/dev/null || git remote add origin "${GIT_REPO_URL}"
        fi
    fi

    log "Pulling latest changes from remote (${BRANCH})..."
    git pull origin "${BRANCH}" --rebase --autostash 2>&1 || log "Warning: git pull failed or remote branch is empty, continuing..."
else
    log "INFO: GIT_REPO_URL is not set or contains placeholder. Git sync will be skipped."
fi

# 2. Sync e0f.cx unified subscription (AmneziaWG + WireGuard + VLESS/Trojan/SS)
if [ -f "${WORKDIR}/sync_subscription.py" ]; then
    log "Syncing e0f.cx unified subscription (AmneziaWG + VLESS)..."
    PYTHONUNBUFFERED=1 "${WORKDIR}/venv/bin/python3" -u "${WORKDIR}/sync_subscription.py" || log "Warning: subscription sync failed, continuing..."
    log "Subscription sync completed."
fi

# 3. Run Python Checker (Gemini Web & API validation)
log "Running proxy checker..."
PYTHONUNBUFFERED=1 "${WORKDIR}/venv/bin/python3" -u "${WORKDIR}/checker.py"
log "Proxy checker finished."

if [ -d ".git" ] && [ -n "${GIT_REPO_URL}" ] && [[ "${GIT_REPO_URL}" != *"USER/REPO"* ]]; then
    CHANGES=0
    if ! git diff --quiet shadowrocket.conf 2>/dev/null || [ -n "$(git status --porcelain shadowrocket.conf 2>/dev/null)" ]; then
        CHANGES=1
    fi

    if [ "${CHANGES}" -eq 1 ]; then
        git add shadowrocket.conf
        git commit -m "Auto-update: All servers (AWG+VLESS) & Gemini filters [skip ci]" || true
        git push -u origin "${BRANCH}"
        log "Successfully pushed updates to ${GIT_REPO_URL} (${BRANCH})."
    else
        log "No changes detected. Nothing to commit."
    fi
fi

log "=========================================================="
log "Gemini Proxy Checker & e0f.cx Sync Completed Successfully"
log "=========================================================="
echo ""
