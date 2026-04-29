#!/bin/bash
# =============================================================================
# install.sh
# WebSphere ND 8.5.5 — Configuration Drift Detection
# PURPOSE: Deploy all scripts to DRIFT_HOME and register the cron job.
#          Run as root (or the OS user that owns the WAS installation).
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# >>>  EDIT THESE  <<<
# ---------------------------------------------------------------------------
DRIFT_HOME="/opt/was-drift"
CRON_USER="wasadmin"           # OS user the cron runs as
CRON_MAILTO="was-alerts@yourcompany.com"
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== WebSphere Drift Monitor — Installer ==="
echo "Deploy target : ${DRIFT_HOME}"
echo "Cron user     : ${CRON_USER}"
echo ""

# Create directory layout
mkdir -p "${DRIFT_HOME}"/{baseline,snapshot,reports,logs}
chmod 750 "${DRIFT_HOME}" "${DRIFT_HOME}"/{baseline,snapshot,reports,logs}

# Deploy scripts
install -m 750 "${SCRIPT_DIR}/extract_baseline.sh" "${DRIFT_HOME}/extract_baseline.sh"
install -m 750 "${SCRIPT_DIR}/check_drift.sh"      "${DRIFT_HOME}/check_drift.sh"
install -m 750 "${SCRIPT_DIR}/drift_email.py"      "${DRIFT_HOME}/drift_email.py"

# Ownership
chown -R "${CRON_USER}:${CRON_USER}" "${DRIFT_HOME}" 2>/dev/null || \
  echo "WARN: Could not chown (may need root). Continuing..."

echo "Scripts deployed to ${DRIFT_HOME}"

# ---------------------------------------------------------------------------
# Register cron — runs every 60 minutes as CRON_USER
# ---------------------------------------------------------------------------
CRON_LINE="0 * * * * MAILTO=${CRON_MAILTO} ${DRIFT_HOME}/check_drift.sh >> ${DRIFT_HOME}/logs/cron.log 2>&1"

# Export current crontab, append if line not already present, reload
( crontab -u "${CRON_USER}" -l 2>/dev/null || true
  echo "# WebSphere ND Drift Monitor — added by install.sh $(date)"
  echo "${CRON_LINE}"
) | sort -u | crontab -u "${CRON_USER}" -

echo ""
echo "Cron registered for user '${CRON_USER}':"
crontab -u "${CRON_USER}" -l | grep "check_drift" || true
echo ""
echo "=== Installation complete ==="
echo ""
echo "NEXT STEPS:"
echo "  1. Edit the variables at the top of:"
echo "       ${DRIFT_HOME}/extract_baseline.sh"
echo "       ${DRIFT_HOME}/check_drift.sh"
echo "     (WAS_HOME, DMGR_PROFILE, DMGR_HOST, DMGR_PORT, WAS_USER, WAS_PASS,"
echo "      CELL_NAME, CLUSTER_NAME, EMAIL_TO, SMTP_HOST)"
echo ""
echo "  2. Run the initial baseline extraction:"
echo "       sudo -u ${CRON_USER} ${DRIFT_HOME}/extract_baseline.sh"
echo ""
echo "  3. Optionally test drift detection immediately:"
echo "       sudo -u ${CRON_USER} ${DRIFT_HOME}/check_drift.sh"
echo "     (exit code 0 = no drift, 1 = drift found)"
echo ""
echo "  4. The cron will now auto-check every 60 minutes and email on drift."
