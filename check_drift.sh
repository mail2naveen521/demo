#!/bin/bash
# =============================================================================
# check_drift.sh
# WebSphere ND 8.5.5 — Configuration Drift Detection
# PURPOSE: Compare current DMGR config against the stored baseline.
#          Invoked by cron every 60 minutes.
#          Sends an HTML email report when drift is detected.
# =============================================================================

set -uo pipefail

# ---------------------------------------------------------------------------
# >>>  EDIT THESE VARIABLES FOR YOUR ENVIRONMENT  <<<
# ---------------------------------------------------------------------------
WAS_HOME="/opt/IBM/WebSphere/AppServer"
DMGR_PROFILE="/opt/IBM/WebSphere/AppServer/profiles/Dmgr01"
DMGR_HOST="localhost"
DMGR_PORT="8879"
WAS_USER="wasadmin"
WAS_PASS="waspassword"
CELL_NAME="MyCell"
CLUSTER_NAME="MyCluster"

DRIFT_HOME="/opt/was-drift"
BASELINE_DIR="${DRIFT_HOME}/baseline"
SNAPSHOT_DIR="${DRIFT_HOME}/snapshot"
REPORT_DIR="${DRIFT_HOME}/reports"
LOG_DIR="${DRIFT_HOME}/logs"
WSADMIN="${WAS_HOME}/bin/wsadmin.sh"
PYTHON_BIN="/usr/bin/python3"                     # For sending email report

# Email settings
EMAIL_TO="was-alerts@yourcompany.com"             # Comma-separated recipients
EMAIL_FROM="was-drift@yourcompany.com"
SMTP_HOST="smtp.yourcompany.com"
SMTP_PORT="25"
# SMTP_USER / SMTP_PASS — set if your relay requires auth (see drift_email.py)
# ---------------------------------------------------------------------------

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="${LOG_DIR}/check_drift_${TIMESTAMP}.log"
REPORT_FILE="${REPORT_DIR}/drift_report_${TIMESTAMP}.json"
DRIFT_FOUND=0

mkdir -p "${SNAPSHOT_DIR}" "${REPORT_DIR}" "${LOG_DIR}"

log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "${LOG_FILE}"; }
die() { log "FATAL: $*"; exit 1; }

log "=========================================================="
log " WebSphere ND 8.5.5 — Drift Check Starting"
log " Timestamp : ${TIMESTAMP}"
log "=========================================================="

# ---------------------------------------------------------------------------
# Sanity checks
# ---------------------------------------------------------------------------
[[ -d "${BASELINE_DIR}" ]]              || die "Baseline directory not found: ${BASELINE_DIR}. Run extract_baseline.sh first."
[[ -f "${BASELINE_DIR}/checksums.sha256" ]] || die "Baseline checksum file missing. Re-run extract_baseline.sh."
[[ -x "${WSADMIN}" ]]                   || die "wsadmin not found/executable: ${WSADMIN}"

# ---------------------------------------------------------------------------
# 1. Clear previous snapshot
# ---------------------------------------------------------------------------
log "Clearing previous snapshot..."
rm -rf "${SNAPSHOT_DIR:?}"/*

# ---------------------------------------------------------------------------
# 2. Copy current DMGR config repository
# ---------------------------------------------------------------------------
DMGR_CONFIG_ROOT="${DMGR_PROFILE}/config"
log "Snapshotting current DMGR config repository..."
cp -rp "${DMGR_CONFIG_ROOT}" "${SNAPSHOT_DIR}/config_repo"

# ---------------------------------------------------------------------------
# 3. Extract current resources.xml files
# ---------------------------------------------------------------------------
log "Extracting current resources.xml files..."
RESOURCES_DIR="${SNAPSHOT_DIR}/resources_xml"
mkdir -p "${RESOURCES_DIR}"
find "${DMGR_CONFIG_ROOT}" -name "resources.xml" | while read -r src; do
    rel_path="${src#${DMGR_CONFIG_ROOT}/}"
    dst="${RESOURCES_DIR}/${rel_path}"
    mkdir -p "$(dirname "${dst}")"
    cp -p "${src}" "${dst}"
done

# ---------------------------------------------------------------------------
# 4. wsadmin live dump of runtime config
# ---------------------------------------------------------------------------
log "Running wsadmin live config dump..."

WSADMIN_SCRIPT=$(mktemp /tmp/was_drift_XXXXXX.py)
cat > "${WSADMIN_SCRIPT}" << 'PYEOF'
import sys, os

outDir = sys.argv[0] if len(sys.argv) > 0 else "/opt/was-drift/snapshot/wsadmin_dump"

def writeFile(path, content):
    d = os.path.dirname(path)
    if not os.path.exists(d):
        os.makedirs(d)
    f = open(path, 'w')
    f.write(str(content))
    f.close()

cell = AdminConfig.getid('/Cell:/')
writeFile(outDir + '/cell_attributes.txt', AdminConfig.show(cell))

clusters = AdminConfig.list('ServerCluster').splitlines()
for c in clusters:
    cname = c.split('(')[0]
    writeFile(outDir + '/cluster_' + cname + '_attrs.txt', AdminConfig.show(c))
    members = AdminConfig.list('ClusterMember', c).splitlines()
    for m in members:
        mname = m.split('(')[0]
        writeFile(outDir + '/cluster_' + cname + '_member_' + mname + '.txt',
                  AdminConfig.show(m))

servers = AdminConfig.list('Server').splitlines()
for s in servers:
    sname = s.split('(')[0]
    if sname in ('dmgr', 'nodeagent'):
        continue
    writeFile(outDir + '/server_' + sname + '_config.txt', AdminConfig.show(s))
    jvms = AdminConfig.list('JavaVirtualMachine', s).splitlines()
    for j in jvms:
        writeFile(outDir + '/server_' + sname + '_jvm.txt', AdminConfig.show(j))
    tps = AdminConfig.list('ThreadPool', s).splitlines()
    for tp in tps:
        tpname = tp.split('(')[0]
        writeFile(outDir + '/server_' + sname + '_threadpool_' + tpname + '.txt',
                  AdminConfig.show(tp))
    txs = AdminConfig.list('TransactionService', s).splitlines()
    for tx in txs:
        writeFile(outDir + '/server_' + sname + '_txservice.txt', AdminConfig.show(tx))

datasources = AdminConfig.list('DataSource').splitlines()
for ds in datasources:
    dsname = ds.split('(')[0].replace('/', '_').replace(':', '_')
    writeFile(outDir + '/datasource_' + dsname + '.txt', AdminConfig.show(ds))
    props = AdminConfig.list('J2EEResourceProperty', ds).splitlines()
    propText = ''
    for p in props:
        propText += AdminConfig.show(p) + '\n'
    if propText:
        writeFile(outDir + '/datasource_' + dsname + '_props.txt', propText)

jdbcProviders = AdminConfig.list('JDBCProvider').splitlines()
for jp in jdbcProviders:
    jpname = jp.split('(')[0].replace('/', '_').replace(':', '_')
    writeFile(outDir + '/jdbc_' + jpname + '.txt', AdminConfig.show(jp))

vhosts = AdminConfig.list('VirtualHost').splitlines()
for vh in vhosts:
    vhname = vh.split('(')[0]
    aliases = AdminConfig.list('HostAlias', vh).splitlines()
    out = AdminConfig.show(vh) + '\n'
    for a in aliases:
        out += '  Alias: ' + AdminConfig.show(a) + '\n'
    writeFile(outDir + '/vhost_' + vhname + '.txt', out)

security = AdminConfig.list('Security').splitlines()
for sec in security:
    writeFile(outDir + '/security_config.txt', AdminConfig.show(sec))

apps = AdminConfig.list('ApplicationDeployment').splitlines()
for app in apps:
    appname = app.split('(')[0].replace('/', '_').replace(':', '_')
    writeFile(outDir + '/app_' + appname + '.txt', AdminConfig.show(app))

vars = AdminConfig.list('VariableSubstitutionEntry').splitlines()
varText = ''
for v in vars:
    varText += AdminConfig.show(v) + '\n'
writeFile(outDir + '/was_variables.txt', varText)

libs = AdminConfig.list('Library').splitlines()
for lib in libs:
    libname = lib.split('(')[0].replace('/', '_').replace(':', '_')
    writeFile(outDir + '/sharedlib_' + libname + '.txt', AdminConfig.show(lib))

print "Live snapshot wsadmin dump complete."
sys.exit(0)
PYEOF

WSADMIN_DUMP_DIR="${SNAPSHOT_DIR}/wsadmin_dump"
mkdir -p "${WSADMIN_DUMP_DIR}"
WSADMIN_OK=true

"${WSADMIN}" \
    -host "${DMGR_HOST}" \
    -port "${DMGR_PORT}" \
    -conntype SOAP \
    -user "${WAS_USER}" \
    -password "${WAS_PASS}" \
    -lang jython \
    -f "${WSADMIN_SCRIPT}" \
    "${WSADMIN_DUMP_DIR}" \
    >> "${LOG_FILE}" 2>&1 || WSADMIN_OK=false

rm -f "${WSADMIN_SCRIPT}"

if [ "${WSADMIN_OK}" = false ]; then
    log "WARNING: wsadmin dump failed — proceeding with file-based comparison only."
fi

# ---------------------------------------------------------------------------
# 5. Compare checksums of the full config_repo
# ---------------------------------------------------------------------------
log "Computing checksums of current snapshot..."
CURRENT_CHECKSUMS="${SNAPSHOT_DIR}/checksums_current.sha256"
find "${SNAPSHOT_DIR}" \
    -not -name "*.sha256" \
    -not -name "*.log" \
    -type f \
    | sort \
    | xargs sha256sum > "${CURRENT_CHECKSUMS}"

# Normalise paths so baseline and snapshot are comparable
# (strip the leading directory prefix down to config_repo/... etc.)
normalise_checksums() {
    local file="$1"
    local strip_prefix="$2"
    sed "s|${strip_prefix}/||g" "${file}" | sort
}

log "Comparing checksums against baseline..."

# Build normalised versions for diffing
BASELINE_NORM=$(mktemp /tmp/baseline_norm_XXXXXX.txt)
CURRENT_NORM=$(mktemp /tmp/current_norm_XXXXXX.txt)
normalise_checksums "${BASELINE_DIR}/checksums.sha256" "${BASELINE_DIR}" > "${BASELINE_NORM}"
normalise_checksums "${CURRENT_CHECKSUMS}"             "${SNAPSHOT_DIR}" > "${CURRENT_NORM}"

CHECKSUM_DIFF=$(diff "${BASELINE_NORM}" "${CURRENT_NORM}" || true)

rm -f "${BASELINE_NORM}" "${CURRENT_NORM}"

# ---------------------------------------------------------------------------
# 6. Deep diff on every changed XML / config file
# ---------------------------------------------------------------------------
declare -A DIFF_MAP        # path → unified diff text
declare -a ADDED_FILES=()
declare -a REMOVED_FILES=()
declare -a CHANGED_FILES=()

if [[ -n "${CHECKSUM_DIFF}" ]]; then
    DRIFT_FOUND=1
    log "Checksum differences detected — performing deep file diff..."

    # Parse added/removed/changed from diff output
    while IFS= read -r line; do
        if [[ "${line}" =~ ^\<[[:space:]]([a-f0-9]+)[[:space:]](.+)$ ]]; then
            REMOVED_FILES+=("${BASH_REMATCH[2]}")
        elif [[ "${line}" =~ ^\>[[:space:]]([a-f0-9]+)[[:space:]](.+)$ ]]; then
            ADDED_FILES+=("${BASH_REMATCH[2]}")
        fi
    done <<< "${CHECKSUM_DIFF}"

    # Files present in both but with different checksums = changed
    for f in "${REMOVED_FILES[@]}"; do
        for g in "${ADDED_FILES[@]}"; do
            if [[ "${f}" == "${g}" ]]; then
                CHANGED_FILES+=("${f}")
            fi
        done
    done

    # Perform actual unified diff for changed files
    for rel_path in "${CHANGED_FILES[@]}"; do
        baseline_file="${BASELINE_DIR}/${rel_path}"
        current_file="${SNAPSHOT_DIR}/${rel_path}"
        if [[ -f "${baseline_file}" && -f "${current_file}" ]]; then
            file_diff=$(diff -u "${baseline_file}" "${current_file}" 2>/dev/null || true)
            if [[ -n "${file_diff}" ]]; then
                DIFF_MAP["${rel_path}"]="${file_diff}"
                log "  CHANGED: ${rel_path}"
            fi
        fi
    done

    # Log purely added/removed
    for f in "${ADDED_FILES[@]}"; do
        local_found=false
        for c in "${CHANGED_FILES[@]}"; do [[ "${f}" == "${c}" ]] && local_found=true && break; done
        if [[ "${local_found}" == false ]]; then
            log "  ADDED  : ${f}"
        fi
    done
    for f in "${REMOVED_FILES[@]}"; do
        local_found=false
        for c in "${CHANGED_FILES[@]}"; do [[ "${f}" == "${c}" ]] && local_found=true && break; done
        if [[ "${local_found}" == false ]]; then
            log "  REMOVED: ${f}"
        fi
    done
else
    log "No checksum differences detected — configuration matches baseline."
fi

# ---------------------------------------------------------------------------
# 7. Specific resources.xml deep diff report
# ---------------------------------------------------------------------------
RESOURCES_DRIFT_DETAIL=""
find "${BASELINE_DIR}/resources_xml" -name "resources.xml" 2>/dev/null | while read -r base_res; do
    rel="${base_res#${BASELINE_DIR}/resources_xml/}"
    curr_res="${SNAPSHOT_DIR}/resources_xml/${rel}"
    if [[ -f "${curr_res}" ]]; then
        rdiff=$(diff -u "${base_res}" "${curr_res}" 2>/dev/null || true)
        if [[ -n "${rdiff}" ]]; then
            echo "RESOURCES_DRIFT:::${rel}:::${rdiff}"
        fi
    else
        echo "RESOURCES_DRIFT:::${rel}:::FILE_REMOVED"
    fi
done > "${REPORT_DIR}/resources_drift_${TIMESTAMP}.txt"

# Check for new resources.xml not in baseline
find "${SNAPSHOT_DIR}/resources_xml" -name "resources.xml" 2>/dev/null | while read -r curr_res; do
    rel="${curr_res#${SNAPSHOT_DIR}/resources_xml/}"
    base_res="${BASELINE_DIR}/resources_xml/${rel}"
    if [[ ! -f "${base_res}" ]]; then
        echo "RESOURCES_DRIFT:::${rel}:::FILE_ADDED"
    fi
done >> "${REPORT_DIR}/resources_drift_${TIMESTAMP}.txt"

# ---------------------------------------------------------------------------
# 8. Write JSON report
# ---------------------------------------------------------------------------
log "Writing drift report: ${REPORT_FILE}"

CHANGED_JSON="["
ADDED_JSON="["
REMOVED_JSON="["
DIFF_DETAILS_JSON="["

for f in "${CHANGED_FILES[@]+"${CHANGED_FILES[@]}"}"; do
    CHANGED_JSON+="\"${f}\","
done
for f in "${ADDED_FILES[@]+"${ADDED_FILES[@]}"}"; do
    # Only truly added (not changed)
    is_changed=false
    for c in "${CHANGED_FILES[@]+"${CHANGED_FILES[@]}"}"; do [[ "$f" == "$c" ]] && is_changed=true; done
    [[ "${is_changed}" == false ]] && ADDED_JSON+="\"${f}\","
done
for f in "${REMOVED_FILES[@]+"${REMOVED_FILES[@]}"}"; do
    is_changed=false
    for c in "${CHANGED_FILES[@]+"${CHANGED_FILES[@]}"}"; do [[ "$f" == "$c" ]] && is_changed=true; done
    [[ "${is_changed}" == false ]] && REMOVED_JSON+="\"${f}\","
done

for rel_path in "${!DIFF_MAP[@]}"; do
    escaped_diff=$(echo "${DIFF_MAP[$rel_path]}" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))")
    DIFF_DETAILS_JSON+="{\"file\":\"${rel_path}\",\"diff\":${escaped_diff}},"
done

# Trim trailing commas
CHANGED_JSON="${CHANGED_JSON%,}]"
ADDED_JSON="${ADDED_JSON%,}]"
REMOVED_JSON="${REMOVED_JSON%,}]"
DIFF_DETAILS_JSON="${DIFF_DETAILS_JSON%,}]"

RESOURCES_DRIFT_COUNT=$(grep -c "RESOURCES_DRIFT" "${REPORT_DIR}/resources_drift_${TIMESTAMP}.txt" 2>/dev/null || echo 0)

python3 - << PYEOF
import json, datetime

report = {
    "check_timestamp": "${TIMESTAMP}",
    "check_time_human": datetime.datetime.now().isoformat(),
    "dmgr_host": "${DMGR_HOST}",
    "cell_name": "${CELL_NAME}",
    "cluster_name": "${CLUSTER_NAME}",
    "drift_detected": ${DRIFT_FOUND} == 1,
    "wsadmin_ok": "${WSADMIN_OK}" == "true",
    "summary": {
        "changed_files": ${CHANGED_JSON},
        "added_files": ${ADDED_JSON},
        "removed_files": ${REMOVED_JSON},
        "resources_xml_drifts": ${RESOURCES_DRIFT_COUNT}
    },
    "diff_details": ${DIFF_DETAILS_JSON},
    "resources_drift_detail_file": "${REPORT_DIR}/resources_drift_${TIMESTAMP}.txt",
    "log_file": "${LOG_FILE}"
}

with open("${REPORT_FILE}", "w") as fh:
    json.dump(report, fh, indent=2)
print("Report written.")
PYEOF

# ---------------------------------------------------------------------------
# 9. Send email if drift detected
# ---------------------------------------------------------------------------
if [[ "${DRIFT_FOUND}" -eq 1 ]]; then
    log "Drift detected — sending email alert..."
    "${PYTHON_BIN}" "${DRIFT_HOME}/drift_email.py" \
        --report    "${REPORT_FILE}" \
        --resources "${REPORT_DIR}/resources_drift_${TIMESTAMP}.txt" \
        --to        "${EMAIL_TO}" \
        --from      "${EMAIL_FROM}" \
        --smtp-host "${SMTP_HOST}" \
        --smtp-port "${SMTP_PORT}" \
        >> "${LOG_FILE}" 2>&1 \
        && log "Email sent successfully." \
        || log "WARNING: Email send failed — check log."
else
    log "No drift — no email sent."
fi

# ---------------------------------------------------------------------------
# 10. Purge reports older than 30 days
# ---------------------------------------------------------------------------
find "${REPORT_DIR}" -name "drift_report_*.json"      -mtime +30 -delete 2>/dev/null || true
find "${REPORT_DIR}" -name "resources_drift_*.txt"    -mtime +30 -delete 2>/dev/null || true
find "${LOG_DIR}"    -name "check_drift_*.log"        -mtime +30 -delete 2>/dev/null || true

log "=========================================================="
log " Drift check COMPLETE  |  Drift found: ${DRIFT_FOUND}"
log " Report: ${REPORT_FILE}"
log "=========================================================="

exit ${DRIFT_FOUND}
