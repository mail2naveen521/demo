#!/usr/bin/env bash
# =============================================================================
# diagnose-xmlaccess.sh
# Reproduces the xmlaccess export OUTSIDE the detector so the real error
# (which capture-baseline.sh hides with >/dev/null 2>&1) is visible.
# Read-only: performs a Portal config EXPORT only, never an import.
# =============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF="${SCRIPT_DIR}/../config/drift-detector.conf"
# shellcheck disable=SC1090
source "$CONF"

echo "=============================================="
echo " xmlaccess export diagnostic"
echo "=============================================="
echo

echo "1) xmlaccess.sh path"
echo "   PORTAL_XMLACCESS_SCRIPT = ${PORTAL_XMLACCESS_SCRIPT}"
if [[ -x "${PORTAL_XMLACCESS_SCRIPT}" ]]; then
    echo "   -> exists and is executable  [OK]"
else
    echo "   -> NOT executable or missing [PROBLEM]"
    echo "      On a Dmgr-only host this script usually does NOT exist;"
    echo "      xmlaccess lives on the Portal NODES, not the Dmgr."
fi
echo

echo "2) Admin password file"
echo "   PORTAL_ADMIN_PASS_FILE = ${PORTAL_ADMIN_PASS_FILE}"
if [[ -r "${PORTAL_ADMIN_PASS_FILE}" ]]; then
    perms=$(stat -c %a "${PORTAL_ADMIN_PASS_FILE}" 2>/dev/null)
    echo "   -> readable, mode ${perms}  [OK]"
    # Warn about a common mistake: trailing newline in the password file
    if [[ "$(tail -c1 "${PORTAL_ADMIN_PASS_FILE}" | wc -l)" -gt 0 ]]; then
        echo "   -> NOTE: file ends with a newline. Some xmlaccess builds"
        echo "      treat the trailing \\n as part of the password and fail"
        echo "      auth. Recreate with: printf '%s' 'PW' > ${PORTAL_ADMIN_PASS_FILE}"
    fi
else
    echo "   -> NOT readable [PROBLEM]"
fi
echo

echo "3) Admin URL reachability"
echo "   PORTAL_ADMIN_URL = ${PORTAL_ADMIN_URL}"
# Parse host:port out of the URL
url_no_scheme="${PORTAL_ADMIN_URL#*://}"
hostport="${url_no_scheme%%/*}"
host="${hostport%%:*}"
port="${hostport##*:}"
[[ "$host" == "$port" ]] && port=80
echo "   host=${host} port=${port}"
if command -v timeout >/dev/null 2>&1; then
    if timeout 5 bash -c "</dev/tcp/${host}/${port}" 2>/dev/null; then
        echo "   -> TCP connect OK  [OK]"
    else
        echo "   -> TCP connect FAILED [PROBLEM]"
        echo "      If you are on the Dmgr host, 'localhost:10039' is wrong."
        echo "      Point PORTAL_ADMIN_URL at a Portal NODE, e.g.:"
        echo "      http://portalnode1.example.com:10039/wps/config"
    fi
fi
echo

echo "4) Live xmlaccess export attempt (full error output)"
echo "   ---------------------------------------------------"
if [[ ! -x "${PORTAL_XMLACCESS_SCRIPT}" || ! -r "${PORTAL_ADMIN_PASS_FILE}" ]]; then
    echo "   Skipped — fix items 1/2 first."
    exit 1
fi

req="$(mktemp /tmp/xmlaccess-req.XXXXXX.xml)"
out="$(mktemp /tmp/xmlaccess-out.XXXXXX.xml)"
cat > "$req" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<request xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:noNamespaceSchemaLocation="PortalConfig_8.5.0.xsd"
         type="export">
    <portal action="export"/>
</request>
EOF

pass="$(< "${PORTAL_ADMIN_PASS_FILE}")"

# Run WITHOUT suppressing output so the real error is visible
"${PORTAL_XMLACCESS_SCRIPT}" \
    -user "${PORTAL_ADMIN_USER}" \
    -password "${pass}" \
    -url "${PORTAL_ADMIN_URL}" \
    -in "$req" \
    -out "$out"
rc=$?

echo "   ---------------------------------------------------"
echo "   xmlaccess exit code: ${rc}"
if [[ $rc -eq 0 ]]; then
    echo "   Export succeeded, $(wc -l < "$out") lines written."
else
    echo "   Export failed — see the xmlaccess output above for the cause."
    echo "   Common causes:"
    echo "     - EJPXB0002E / connection refused : URL points where no Portal runs"
    echo "     - EJPXB0508E / authized failed    : wrong user/password (or trailing \\n)"
    echo "     - 404 / wrong context root        : Portal up but /wps/config disabled"
fi
rm -f "$req" "$out"
exit $rc
