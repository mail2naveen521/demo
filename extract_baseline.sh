#!/bin/bash
# =============================================================================
# extract_baseline.sh
# WebSphere ND 8.5.5 — Configuration Drift Detection
# PURPOSE: Extract a full baseline snapshot from the DMGR.
#          Run this ONCE (or whenever you want to reset the baseline).
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# >>>  EDIT THESE VARIABLES FOR YOUR ENVIRONMENT  <<<
# ---------------------------------------------------------------------------
WAS_HOME="/opt/IBM/WebSphere/AppServer"          # WAS installation root
DMGR_PROFILE="/opt/IBM/WebSphere/AppServer/profiles/Dmgr01"
DMGR_HOST="localhost"                             # DMGR SOAP host
DMGR_PORT="8879"                                  # DMGR SOAP connector port
WAS_USER="wasadmin"                               # WAS admin user
WAS_PASS="waspassword"                            # WAS admin password
CELL_NAME="MyCell"                                # WebSphere cell name
CLUSTER_NAME="MyCluster"                          # Cluster name

DRIFT_HOME="/opt/was-drift"                       # Base dir for drift tool
BASELINE_DIR="${DRIFT_HOME}/baseline"
LOG_DIR="${DRIFT_HOME}/logs"
WSADMIN="${WAS_HOME}/bin/wsadmin.sh"
# ---------------------------------------------------------------------------

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="${LOG_DIR}/extract_baseline_${TIMESTAMP}.log"

mkdir -p "${BASELINE_DIR}" "${LOG_DIR}"

log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "${LOG_FILE}"; }

log "=========================================================="
log " WebSphere ND 8.5.5 — Baseline Extraction Starting"
log "=========================================================="
log " DMGR Profile : ${DMGR_PROFILE}"
log " Baseline Dir : ${BASELINE_DIR}"
log " Cell         : ${CELL_NAME}"
log " Cluster      : ${CLUSTER_NAME}"
log "=========================================================="

# ---------------------------------------------------------------------------
# 1. Wipe any previous baseline
# ---------------------------------------------------------------------------
log "Clearing previous baseline..."
rm -rf "${BASELINE_DIR:?}"/*

# ---------------------------------------------------------------------------
# 2. Copy the DMGR config repository (config/cells tree) — the authoritative
#    source of truth for WebSphere ND configuration.
# ---------------------------------------------------------------------------
DMGR_CONFIG_ROOT="${DMGR_PROFILE}/config"

log "Snapshotting DMGR config repository → ${BASELINE_DIR}/config_repo ..."
cp -rp "${DMGR_CONFIG_ROOT}" "${BASELINE_DIR}/config_repo"

# ---------------------------------------------------------------------------
# 3. Extract resources.xml files explicitly (belt-and-suspenders — they live
#    inside the config repo, but we keep a dedicated copy for targeted diffing)
# ---------------------------------------------------------------------------
log "Extracting all resources.xml files..."
RESOURCES_DIR="${BASELINE_DIR}/resources_xml"
mkdir -p "${RESOURCES_DIR}"

# Preserve directory structure relative to config root
find "${DMGR_CONFIG_ROOT}" -name "resources.xml" | while read -r src; do
    rel_path="${src#${DMGR_CONFIG_ROOT}/}"
    dst="${RESOURCES_DIR}/${rel_path}"
    mkdir -p "$(dirname "${dst}")"
    cp -p "${src}" "${dst}"
    log "  Captured: ${rel_path}"
done

# ---------------------------------------------------------------------------
# 4. Use wsadmin to dump live runtime config that may not be fully reflected
#    in flat files (JVM args, thread pools, datasource props, etc.)
# ---------------------------------------------------------------------------
log "Running wsadmin to dump server/cluster runtime configuration..."

WSADMIN_SCRIPT=$(mktemp /tmp/was_baseline_XXXXXX.py)
cat > "${WSADMIN_SCRIPT}" << 'PYEOF'
import sys, os

outDir = sys.argv[0] if len(sys.argv) > 0 else "/opt/was-drift/baseline/wsadmin_dump"

def writeFile(path, content):
    d = os.path.dirname(path)
    if not os.path.exists(d):
        os.makedirs(d)
    f = open(path, 'w')
    f.write(str(content))
    f.close()

# --- Cell-level attributes ---
cell = AdminConfig.getid('/Cell:/')
writeFile(outDir + '/cell_attributes.txt', AdminConfig.show(cell))

# --- All clusters ---
clusters = AdminConfig.list('ServerCluster').splitlines()
for c in clusters:
    cname = c.split('(')[0]
    writeFile(outDir + '/cluster_' + cname + '_attrs.txt', AdminConfig.show(c))
    members = AdminConfig.list('ClusterMember', c).splitlines()
    for m in members:
        mname = m.split('(')[0]
        writeFile(outDir + '/cluster_' + cname + '_member_' + mname + '.txt',
                  AdminConfig.show(m))

# --- All application servers ---
servers = AdminConfig.list('Server').splitlines()
for s in servers:
    sname = s.split('(')[0]
    if sname in ('dmgr', 'nodeagent'):
        continue
    writeFile(outDir + '/server_' + sname + '_config.txt', AdminConfig.show(s))
    # JVM
    jvms = AdminConfig.list('JavaVirtualMachine', s).splitlines()
    for j in jvms:
        writeFile(outDir + '/server_' + sname + '_jvm.txt', AdminConfig.show(j))
    # Thread pools
    tps = AdminConfig.list('ThreadPool', s).splitlines()
    for tp in tps:
        tpname = tp.split('(')[0]
        writeFile(outDir + '/server_' + sname + '_threadpool_' + tpname + '.txt',
                  AdminConfig.show(tp))
    # Transaction service
    txs = AdminConfig.list('TransactionService', s).splitlines()
    for tx in txs:
        writeFile(outDir + '/server_' + sname + '_txservice.txt', AdminConfig.show(tx))

# --- DataSources (cell + node scopes) ---
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

# --- JDBC Providers ---
jdbcProviders = AdminConfig.list('JDBCProvider').splitlines()
for jp in jdbcProviders:
    jpname = jp.split('(')[0].replace('/', '_').replace(':', '_')
    writeFile(outDir + '/jdbc_' + jpname + '.txt', AdminConfig.show(jp))

# --- Virtual Hosts ---
vhosts = AdminConfig.list('VirtualHost').splitlines()
for vh in vhosts:
    vhname = vh.split('(')[0]
    aliases = AdminConfig.list('HostAlias', vh).splitlines()
    out = AdminConfig.show(vh) + '\n'
    for a in aliases:
        out += '  Alias: ' + AdminConfig.show(a) + '\n'
    writeFile(outDir + '/vhost_' + vhname + '.txt', out)

# --- Security config ---
security = AdminConfig.list('Security').splitlines()
for sec in security:
    writeFile(outDir + '/security_config.txt', AdminConfig.show(sec))

# --- Deployed applications ---
apps = AdminConfig.list('ApplicationDeployment').splitlines()
for app in apps:
    appname = app.split('(')[0].replace('/', '_').replace(':', '_')
    writeFile(outDir + '/app_' + appname + '.txt', AdminConfig.show(app))

# --- Environment variables (WebSphere variables) ---
vars = AdminConfig.list('VariableSubstitutionEntry').splitlines()
varText = ''
for v in vars:
    varText += AdminConfig.show(v) + '\n'
writeFile(outDir + '/was_variables.txt', varText)

# --- Shared Libraries ---
libs = AdminConfig.list('Library').splitlines()
for lib in libs:
    libname = lib.split('(')[0].replace('/', '_').replace(':', '_')
    writeFile(outDir + '/sharedlib_' + libname + '.txt', AdminConfig.show(lib))

print "Baseline wsadmin dump complete."
sys.exit(0)
PYEOF

WSADMIN_DUMP_DIR="${BASELINE_DIR}/wsadmin_dump"
mkdir -p "${WSADMIN_DUMP_DIR}"

"${WSADMIN}" \
    -host "${DMGR_HOST}" \
    -port "${DMGR_PORT}" \
    -conntype SOAP \
    -user "${WAS_USER}" \
    -password "${WAS_PASS}" \
    -lang jython \
    -f "${WSADMIN_SCRIPT}" \
    "${WSADMIN_DUMP_DIR}" \
    >> "${LOG_FILE}" 2>&1 && log "wsadmin dump succeeded." \
    || log "WARNING: wsadmin dump encountered errors — check log. File-based baseline still valid."

rm -f "${WSADMIN_SCRIPT}"

# ---------------------------------------------------------------------------
# 5. Compute SHA-256 checksums over every captured file
# ---------------------------------------------------------------------------
log "Computing checksums for all baseline files..."
CHECKSUM_FILE="${BASELINE_DIR}/checksums.sha256"

find "${BASELINE_DIR}" \
    -not -name "checksums.sha256" \
    -not -name "*.log" \
    -type f \
    | sort \
    | xargs sha256sum > "${CHECKSUM_FILE}"

TOTAL=$(wc -l < "${CHECKSUM_FILE}")
log "Checksum file written: ${CHECKSUM_FILE} (${TOTAL} files)"

# ---------------------------------------------------------------------------
# 6. Record baseline metadata
# ---------------------------------------------------------------------------
META_FILE="${BASELINE_DIR}/baseline_meta.txt"
cat > "${META_FILE}" << EOF
baseline_created=$(date --iso-8601=seconds)
dmgr_host=${DMGR_HOST}
dmgr_port=${DMGR_PORT}
cell_name=${CELL_NAME}
cluster_name=${CLUSTER_NAME}
was_home=${WAS_HOME}
dmgr_profile=${DMGR_PROFILE}
files_captured=${TOTAL}
extracted_by=$(whoami)
hostname=$(hostname -f)
EOF

log ""
log "=========================================================="
log " Baseline extraction COMPLETE"
log " Files captured : ${TOTAL}"
log " Meta           : ${META_FILE}"
log " Checksums      : ${CHECKSUM_FILE}"
log " Log            : ${LOG_FILE}"
log "=========================================================="
