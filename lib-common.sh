#!/usr/bin/env bash
# =============================================================================
# Common library functions for the drift detector.
# Sourced by capture-baseline.sh and check-drift.sh.
# =============================================================================

set -o pipefail

# ---------- Logging ----------------------------------------------------------
log() {
    local level="$1"; shift
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[${ts}] [${level}] $*" | tee -a "${LOG_DIR}/drift-detector.log" >&2
}
log_info()  { log "INFO"  "$*"; }
log_warn()  { log "WARN"  "$*"; }
log_error() { log "ERROR" "$*"; }

die() {
    log_error "$*"
    exit 1
}

# ---------- Path / target resolution -----------------------------------------
resolve_targets() {
    local p
    for sub in ${WAS_WATCH_DIRS}; do
        p="${WAS_PROFILE_ROOT}/${WAS_PROFILE_NAME}/${sub}"
        [[ -d "$p" ]] && echo "$p"
    done
    for p in "${PORTAL_CONFIG_DIR}" "${PORTAL_PROPERTIES_DIR}" "${PORTAL_THEMES_DIR}"; do
        [[ -d "$p" ]] && echo "$p"
    done
}

# Run find across all targets with INCLUDE_PATTERNS as literal -name args.
# Globbing is disabled to keep *.xml etc. literal.
find_candidate_files() {
    local targets=()
    while IFS= read -r d; do
        targets+=("$d")
    done < <(resolve_targets)
    [[ ${#targets[@]} -eq 0 ]] && return 0

    local find_args=( "${targets[@]}" -type f \( )
    local first=1 pat
    set -f
    for pat in ${INCLUDE_PATTERNS}; do
        if (( first )); then
            find_args+=( -name "$pat" )
            first=0
        else
            find_args+=( -o -name "$pat" )
        fi
    done
    set +f
    find_args+=( \) )

    find "${find_args[@]}" 2>/dev/null
}

# 0 = exclude, 1 = keep
should_exclude() {
    local file="$1"
    local pat
    set -f
    for pat in ${EXCLUDE_PATTERNS}; do
        # shellcheck disable=SC2053
        if [[ "$file" == *"$pat"* || "$file" == $pat ]]; then
            set +f
            return 0
        fi
    done
    set +f
    return 1
}

# ---------- Hashing ----------------------------------------------------------
hash_file() {
    local file="$1"
    if file -b --mime "$file" 2>/dev/null | grep -q 'charset=binary'; then
        sha256sum "$file" | awk '{print $1}'
        return
    fi
    if [[ -s "${SCRUB_PATTERNS_FILE:-}" ]]; then
        local sed_args=()
        local line
        # Use Ctrl-A (0x01) as the s/// delimiter. Regex patterns legitimately
        # contain | / and other punctuation; a non-printing delimiter that
        # never appears in config text avoids breaking the substitution.
        local D=$'\001'
        while IFS= read -r line; do
            [[ -z "$line" || "$line" =~ ^# ]] && continue
            sed_args+=( -e "s${D}${line}${D}${D}g" )
        done < "${SCRUB_PATTERNS_FILE}"
        if [[ ${#sed_args[@]} -gt 0 ]]; then
            # -E for extended regex so {n,m}, +, ?, (), | work without backslash escapes
            sed -E "${sed_args[@]}" "$file" 2>/dev/null | sha256sum | awk '{print $1}'
            return
        fi
    fi
    sha256sum "$file" | awk '{print $1}'
}

# ---------- Snapshot generation ---------------------------------------------
# Dedupe by absolute path: overlapping watch dirs (e.g. WAS_WATCH_DIRS includes
# PortalServer/config AND PORTAL_CONFIG_DIR points to the same place) must not
# produce duplicate entries.
generate_snapshot() {
    local f
    find_candidate_files | LC_ALL=C sort -u | while IFS= read -r f; do
        should_exclude "$f" && continue
        [[ -r "$f" ]] || continue
        printf '%s  %s\n' "$(hash_file "$f")" "$f"
    done | LC_ALL=C sort -k2
}

# ---------- Portal XMLAccess export -----------------------------------------
export_portal_xmlaccess() {
    local outdir="$1"
    local outfile="${outdir}/portal-xmlaccess-export.xml"

    if [[ ! -x "${PORTAL_XMLACCESS_SCRIPT}" ]]; then
        log_info "xmlaccess.sh not found at ${PORTAL_XMLACCESS_SCRIPT}; skipping portal logical export"
        return 0
    fi
    if [[ ! -r "${PORTAL_ADMIN_PASS_FILE}" ]]; then
        log_warn "Portal admin password file not readable; skipping xmlaccess export"
        return 0
    fi

    local req="${outdir}/.xml-export-request.xml"
    cat > "$req" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<request xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:noNamespaceSchemaLocation="PortalConfig_8.5.0.xsd"
         type="export">
    <portal action="export"/>
</request>
EOF

    local pass
    pass="$(< "${PORTAL_ADMIN_PASS_FILE}")"

    if "${PORTAL_XMLACCESS_SCRIPT}" \
        -user "${PORTAL_ADMIN_USER}" \
        -password "${pass}" \
        -url "${PORTAL_ADMIN_URL}" \
        -in "$req" \
        -out "$outfile" >/dev/null 2>&1; then
        rm -f "$req"
        echo "$outfile"
    else
        log_warn "xmlaccess export failed; portal logical config will not be tracked"
        rm -f "$req"
    fi
}
