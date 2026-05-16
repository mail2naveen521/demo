#!/usr/bin/env bash
# =============================================================================
# preflight.sh
# Verifies the host is ready to run the drift detector.
# Checks: OS, required tools, optional tools, config paths, permissions, mail.
# Run BEFORE capture-baseline.sh.
# Exit 0 = ready, 1 = required missing, 2 = warnings only
# =============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF="${SCRIPT_DIR}/../config/drift-detector.conf"

if [[ -r "$CONF" ]]; then
    # shellcheck disable=SC1090
    source "$CONF"
fi

ERRORS=0
WARNINGS=0

# ---- pretty-print helpers ---------------------------------------------------
if [[ -t 1 ]]; then
    G='\033[0;32m'; Y='\033[0;33m'; R='\033[0;31m'; B='\033[1m'; N='\033[0m'
else
    G=''; Y=''; R=''; B=''; N=''
fi

pass() { printf "  ${G}✓${N} %s\n" "$*"; }
warn() { printf "  ${Y}!${N} %s\n" "$*"; WARNINGS=$((WARNINGS+1)); }
fail() { printf "  ${R}✗${N} %s\n" "$*"; ERRORS=$((ERRORS+1)); }
section() { printf "\n${B}== %s ==${N}\n" "$*"; }

# ---- OS check ---------------------------------------------------------------
section "Operating system"
if [[ -r /etc/redhat-release ]]; then
    rel="$(cat /etc/redhat-release)"
    if grep -qE 'release 8\.' /etc/redhat-release; then
        pass "RHEL/CentOS 8 detected: $rel"
    elif grep -qE 'release 9\.' /etc/redhat-release; then
        pass "RHEL/CentOS 9 detected: $rel (tested on 8, should work)"
    else
        warn "Red Hat family but not RHEL 8/9: $rel — proceed with caution"
    fi
elif [[ -r /etc/os-release ]]; then
    . /etc/os-release
    warn "Not RHEL — detected: ${PRETTY_NAME:-unknown}. Should still work on most Linux."
else
    warn "Cannot identify OS"
fi

# Kernel — inotify needs >= 2.6.13, anything in this decade is fine
pass "Kernel: $(uname -r)"

# ---- Required tools ---------------------------------------------------------
section "Required tools"
check_required() {
    local tool="$1"
    local pkg_hint="${2:-$1}"
    if command -v "$tool" >/dev/null 2>&1; then
        pass "$tool found: $(command -v "$tool")"
    else
        fail "$tool NOT found — install with: sudo dnf install -y $pkg_hint"
    fi
}

check_required bash
check_required sha256sum coreutils
check_required find findutils
check_required sort coreutils
check_required awk gawk
check_required sed sed
check_required diff diffutils
check_required file file
check_required python3 python3

# bash version
if [[ -n "${BASH_VERSION:-}" ]]; then
    maj="${BASH_VERSION%%.*}"
    if (( maj >= 4 )); then
        pass "bash $BASH_VERSION (>= 4.0 required)"
    else
        fail "bash $BASH_VERSION too old; need 4.0+ for associative arrays"
    fi
fi

# python3 version (need 3.6+ for email.message.EmailMessage with attachments)
if command -v python3 >/dev/null 2>&1; then
    pyver="$(python3 -c 'import sys; print(".".join(map(str,sys.version_info[:2])))')"
    if python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,6) else 1)'; then
        pass "python3 $pyver (>= 3.6 required)"
    else
        fail "python3 $pyver too old; need 3.6+"
    fi
fi

# ---- Optional tools ---------------------------------------------------------
section "Optional tools"

if command -v inotifywait >/dev/null 2>&1; then
    pass "inotifywait found — real-time watcher available"
else
    warn "inotifywait not found — real-time watcher will NOT work."
    warn "  Install: sudo dnf install -y epel-release && sudo dnf install -y inotify-tools"
    warn "  (Cron / systemd timer mode works without this)"
fi

# RHEL 8 replaced mailx with s-nail; either provides the 'mailx' command
if command -v mailx >/dev/null 2>&1; then
    pass "mailx found — fallback mail transport available"
elif command -v s-nail >/dev/null 2>&1; then
    pass "s-nail found — fallback mail transport available (provides mailx)"
else
    warn "No mailx/s-nail — only Python SMTP path will work (usually fine)."
    warn "  To enable mailx fallback: sudo dnf install -y s-nail"
fi

# Crond — only needed if using install-cron.sh path
if systemctl list-unit-files crond.service >/dev/null 2>&1; then
    if systemctl is-active --quiet crond.service; then
        pass "crond is active (cron schedule mode available)"
    else
        warn "crond installed but not active — start with: sudo systemctl enable --now crond"
    fi
else
    warn "crond not installed — install with: sudo dnf install -y cronie"
fi

# Systemd — used by the timer/watch units
if command -v systemctl >/dev/null 2>&1; then
    pass "systemctl found — systemd timer/service mode available"
fi

# ---- WebSphere paths --------------------------------------------------------
section "WebSphere paths"
check_dir() {
    local path="$1"; local label="$2"; local required="${3:-no}"
    if [[ -d "$path" ]]; then
        if [[ -r "$path" ]]; then
            local cnt
            cnt=$(find "$path" -maxdepth 1 -type f 2>/dev/null | wc -l)
            pass "$label exists and is readable: $path (${cnt} files at top level)"
        else
            fail "$label exists but is NOT readable by $(id -un): $path"
        fi
    else
        if [[ "$required" == "yes" ]]; then
            fail "$label MISSING (required): $path"
        else
            warn "$label not present: $path"
        fi
    fi
}

check_dir "$WAS_HOME" "WAS_HOME (product binaries)" no
check_dir "$WAS_PROFILE_ROOT/$WAS_PROFILE_NAME" "WAS profile (${WAS_PROFILE_NAME})" yes
check_dir "$WAS_PROFILE_ROOT/$WAS_PROFILE_NAME/config/cells" "Profile cells dir" yes
check_dir "$WAS_PROFILE_ROOT/$WAS_PROFILE_NAME/properties" "Profile properties dir" yes

# ---- HCL Portal paths -------------------------------------------------------
section "HCL Portal paths"
check_dir "$PORTAL_HOME" "PORTAL_HOME (binaries)" no
check_dir "$PORTAL_CONFIG_DIR" "Portal service config (wp_profile/PortalServer/config)" no
check_dir "$PORTAL_PROPERTIES_DIR" "WCM service config (wp_profile/.../wcmservices)" no
check_dir "$PORTAL_THEMES_DIR" "Portal themes dir" no

if [[ -x "$PORTAL_XMLACCESS_SCRIPT" ]]; then
    pass "xmlaccess.sh found and executable: $PORTAL_XMLACCESS_SCRIPT"
    if [[ -r "$PORTAL_ADMIN_PASS_FILE" ]]; then
        perms=$(stat -c %a "$PORTAL_ADMIN_PASS_FILE" 2>/dev/null)
        if [[ "$perms" == "600" || "$perms" == "400" ]]; then
            pass "Portal admin password file readable, mode $perms: $PORTAL_ADMIN_PASS_FILE"
        else
            warn "Portal admin password file mode is $perms; should be 600 or 400"
        fi
    else
        warn "Portal admin password file missing/unreadable: $PORTAL_ADMIN_PASS_FILE"
        warn "  xmlaccess export will be skipped (file-level monitoring still works)"
    fi
else
    warn "xmlaccess.sh not found at $PORTAL_XMLACCESS_SCRIPT — logical config won't be captured"
fi

# ---- Drift detector own paths ----------------------------------------------
section "Drift detector paths"
for d in "$BASELINE_DIR" "$REPORT_DIR" "$LOG_DIR" "$DIFF_SNAPSHOT_DIR"; do
    if [[ -d "$d" ]]; then
        if [[ -w "$d" ]]; then
            pass "Writable: $d"
        else
            fail "Not writable by $(id -un): $d"
        fi
    else
        if mkdir -p "$d" 2>/dev/null; then
            pass "Created: $d"
        else
            fail "Cannot create: $d"
        fi
    fi
done

if [[ -r "$SCRUB_PATTERNS_FILE" ]]; then
    pass "Scrub patterns file readable: $SCRUB_PATTERNS_FILE"
else
    warn "Scrub patterns file missing: $SCRUB_PATTERNS_FILE (false positives more likely)"
fi

# ---- Mail configuration -----------------------------------------------------
section "Mail configuration"
if [[ "${MAIL_ENABLED:-true}" != "true" ]]; then
    warn "MAIL_ENABLED=false — no emails will be sent"
else
    [[ -n "$MAIL_FROM" ]] && pass "MAIL_FROM: $MAIL_FROM" || fail "MAIL_FROM not set"
    [[ -n "$MAIL_TO" ]]   && pass "MAIL_TO: $MAIL_TO"     || fail "MAIL_TO not set"
    [[ -n "$MAIL_SMTP_HOST" ]] && pass "SMTP host: $MAIL_SMTP_HOST:$MAIL_SMTP_PORT" \
                               || fail "MAIL_SMTP_HOST not set"

    # Best-effort TCP probe with timeout/bash builtins
    if command -v timeout >/dev/null 2>&1 && [[ -n "${MAIL_SMTP_HOST:-}" ]]; then
        if timeout 5 bash -c "</dev/tcp/${MAIL_SMTP_HOST}/${MAIL_SMTP_PORT}" 2>/dev/null; then
            pass "SMTP TCP reachable: ${MAIL_SMTP_HOST}:${MAIL_SMTP_PORT}"
        else
            warn "SMTP TCP connect failed: ${MAIL_SMTP_HOST}:${MAIL_SMTP_PORT}"
            warn "  Either host unreachable, firewalled, or not yet started"
        fi
    fi

    if [[ -n "${MAIL_SMTP_PASS_FILE:-}" ]]; then
        if [[ -r "$MAIL_SMTP_PASS_FILE" ]]; then
            perms=$(stat -c %a "$MAIL_SMTP_PASS_FILE" 2>/dev/null)
            if [[ "$perms" == "600" || "$perms" == "400" ]]; then
                pass "SMTP password file mode $perms: $MAIL_SMTP_PASS_FILE"
            else
                warn "SMTP password file mode is $perms; should be 600 or 400"
            fi
        else
            warn "MAIL_SMTP_PASS_FILE configured but unreadable: $MAIL_SMTP_PASS_FILE"
        fi
    fi
fi

# ---- SELinux note -----------------------------------------------------------
section "SELinux"
if command -v getenforce >/dev/null 2>&1; then
    mode="$(getenforce 2>/dev/null)"
    case "$mode" in
        Enforcing)
            warn "SELinux is Enforcing. If cron/systemd-spawned check-drift can't read"
            warn "  WAS config, you may need: sudo setsebool -P daemons_dump_core 1"
            warn "  or label the binary: sudo chcon -t bin_t /opt/drift-detector/bin/*.sh"
            ;;
        Permissive) pass "SELinux Permissive — no restrictions enforced" ;;
        Disabled)   pass "SELinux Disabled" ;;
        *)          warn "SELinux state unknown: $mode" ;;
    esac
else
    pass "SELinux tools absent — not enforced"
fi

# ---- firewalld note (only if SMTP is remote) --------------------------------
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    section "firewalld"
    pass "firewalld is active — ensure outbound SMTP (port $MAIL_SMTP_PORT) is permitted"
fi

# ---- Summary ----------------------------------------------------------------
section "Summary"
printf "  Errors:   ${R}%d${N}\n" "$ERRORS"
printf "  Warnings: ${Y}%d${N}\n" "$WARNINGS"
echo

if (( ERRORS > 0 )); then
    printf "${R}NOT READY${N} — fix the errors above before running capture-baseline.sh\n"
    exit 1
elif (( WARNINGS > 0 )); then
    printf "${Y}READY with warnings${N} — review optional items above\n"
    exit 2
else
    printf "${G}READY${N} — run bin/capture-baseline.sh next\n"
    exit 0
fi
