# =============================================================================
# WebSphere Configuration Drift Monitor - Drift Detector
# Target: WAS ND 8.5.5.27, Jython 2.1 (Python 2.1 syntax only)
# Run: wsadmin.sh -lang jython -f detect_drift.py
# =============================================================================

import os
import sys
import time
import re
import smtplib

from java.security import MessageDigest
from java.lang import String as JString

# =============================================================================
# CONFIGURATION - Edit before deployment
# =============================================================================
BASELINE_DIR  = "/opt/drift-monitor/baseline"
SNAPSHOT_DIR  = "/opt/drift-monitor/snapshots"
REPORT_DIR    = "/opt/drift-monitor/reports"
LOG_FILE      = "/opt/drift-monitor/logs/drift.log"
SCRIPTS_DIR   = "/opt/drift-monitor/scripts"

# Email via unauthenticated internal SMTP relay on port 25 - no password needed
SMTP_HOST     = "mailrelay.yourcompany.com"
EMAIL_FROM    = "was-monitor@yourcompany.com"
EMAIL_TO      = ["websphere-ops@yourcompany.com", "middleware-team@yourcompany.com"]

# Attributes excluded from drift comparison (transient metadata)
IGNORED_ATTRS = ["lastModified", "modifiedBy", "deploymentDescriptorVersion"]

# Sections whose changes are always classified as CRITICAL severity
CRITICAL_SECTIONS = ["security", "ssl", "servers", "clusters", "datasources"]

# =============================================================================
# LOGGING
# =============================================================================

def log(msg):
    ts   = time.strftime("%Y-%m-%d %H:%M:%S")
    line = "[%s] %s" % (ts, msg)
    print line
    try:
        fh = open(LOG_FILE, "a")
        fh.write(line + "\n")
        fh.close()
    except:
        pass


def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)


# =============================================================================
# SHA-256 (no hashlib in Jython 2.1)
# =============================================================================

def sha256(s):
    md   = MessageDigest.getInstance("SHA-256")
    raw  = md.digest(JString(s).getBytes("UTF-8"))
    hexc = "0123456789abcdef"
    out  = []
    for b in raw:
        ub = b & 0xFF
        out.append(hexc[ub >> 4])
        out.append(hexc[ub & 0x0F])
    return "".join(out)


# =============================================================================
# JSON SERIALISER (no json module in Jython 2.1)
# =============================================================================

_T_INT   = type(0)
_T_FLOAT = type(0.0)
_T_STR   = type("")
_T_LIST  = type([])
_T_TUPLE = type(())
_T_DICT  = type({})


def _jesc(s):
    s = str(s)
    s = s.replace("\\", "\\\\")
    s = s.replace('"',  '\\"')
    s = s.replace("\n", "\\n")
    s = s.replace("\r", "\\r")
    s = s.replace("\t", "\\t")
    return s


def _jdumps(obj, ind=0):
    sp  = " " * ind
    sp2 = " " * (ind + 2)
    t   = type(obj)

    if obj is None:
        return "null"

    if t == _T_INT or t == _T_FLOAT:
        return str(obj)

    if t == _T_STR:
        return '"' + _jesc(obj) + '"'

    if t == _T_LIST or t == _T_TUPLE:
        if not obj:
            return "[]"
        parts = []
        for v in obj:
            parts.append(sp2 + _jdumps(v, ind + 2))
        return "[\n" + ",\n".join(parts) + "\n" + sp + "]"

    if t == _T_DICT:
        if not obj:
            return "{}"
        keys = list(obj.keys())
        keys.sort()
        parts = []
        for k in keys:
            parts.append(sp2 + '"' + _jesc(str(k)) + '": ' + _jdumps(obj[k], ind + 2))
        return "{\n" + ",\n".join(parts) + "\n" + sp + "}"

    # unicode and any other type
    return '"' + _jesc(str(obj)) + '"'


# =============================================================================
# JSON PARSER (no json module in Jython 2.1)
# =============================================================================

def _jskip(s, p):
    while p < len(s) and s[p] in " \t\n\r":
        p += 1
    return p


def _jparse(s, p):
    p = _jskip(s, p)
    c = s[p]

    if c == '"':
        p   += 1
        buf  = []
        esc  = {"n": "\n", "r": "\r", "t": "\t",
                '"': '"', "\\": "\\", "/": "/"}
        while p < len(s):
            ch = s[p]
            if ch == '"':
                return "".join(buf), p + 1
            if ch == '\\':
                p += 1
                buf.append(esc.get(s[p], s[p]))
            else:
                buf.append(ch)
            p += 1
        raise ValueError("Unterminated string")

    if c == '{':
        p  += 1
        obj = {}
        while 1:
            p = _jskip(s, p)
            if s[p] == '}':
                return obj, p + 1
            if s[p] == ',':
                p += 1
                continue
            k, p = _jparse(s, p)
            p = _jskip(s, p)
            p += 1
            v, p = _jparse(s, p)
            obj[k] = v

    if c == '[':
        p   += 1
        arr  = []
        while 1:
            p = _jskip(s, p)
            if s[p] == ']':
                return arr, p + 1
            if s[p] == ',':
                p += 1
                continue
            v, p = _jparse(s, p)
            arr.append(v)

    if s[p:p+4] == "null":  return None, p + 4
    if s[p:p+4] == "true":  return 1,    p + 4
    if s[p:p+5] == "false": return 0,    p + 5

    end = p
    while end < len(s) and s[end] not in " \t\n\r,}]":
        end += 1
    tok = s[p:end]
    try:
        return int(tok), end
    except ValueError:
        return float(tok), end


def _jloads(s):
    val, _ = _jparse(s, 0)
    return val


# =============================================================================
# FILE HELPERS
# =============================================================================

def write_json(path, data):
    fh = open(path, "w")
    fh.write(_jdumps(data))
    fh.close()


def read_json(path):
    fh   = open(path, "r")
    text = fh.read()
    fh.close()
    return _jloads(text)


def list_files(directory, prefix):
    if not os.path.exists(directory):
        return []
    result = []
    for fname in os.listdir(directory):
        if fname[:len(prefix)] == prefix:
            result.append(fname)
    result.sort()
    return result


def cleanup_old_files(directory, prefix, keep=72):
    files = list_files(directory, prefix)
    if len(files) > keep:
        for old in files[:-keep]:
            try:
                os.remove(os.path.join(directory, old))
            except:
                pass


# =============================================================================
# DIFF ENGINE
# =============================================================================

def _is_ignored(key):
    for ig in IGNORED_ATTRS:
        if ig == key:
            return 1
    return 0


def parse_was_attrs(attr_str):
    attrs = {}
    for m in re.finditer(r"\[(\S+)\s+(.*?)\]", attr_str):
        key = m.group(1)
        if not _is_ignored(key):
            attrs[key] = m.group(2).strip()
    return attrs


def diff_attr_strings(b_str, l_str, path):
    changes = []
    b_attrs = parse_was_attrs(b_str)
    l_attrs = parse_was_attrs(l_str)

    all_keys = {}
    for k in b_attrs.keys():
        all_keys[k] = 1
    for k in l_attrs.keys():
        all_keys[k] = 1
    keys = list(all_keys.keys())
    keys.sort()

    for key in keys:
        bv = b_attrs.get(key, "<MISSING>")
        lv = l_attrs.get(key, "<MISSING>")
        if bv != lv:
            if bv == "<MISSING>":
                ctype = "ADDED"
            elif lv == "<MISSING>":
                ctype = "REMOVED"
            else:
                ctype = "MODIFIED"
            changes.append({
                "path":           "%s.%s" % (path, key),
                "baseline_value": bv,
                "live_value":     lv,
                "change_type":    ctype,
            })
    return changes


def _is_str(v):
    return type(v) == _T_STR


def diff_section(b_data, l_data, path):
    changes = []

    if type(b_data) == _T_DICT and type(l_data) == _T_DICT:
        all_keys = {}
        for k in b_data.keys():
            all_keys[k] = 1
        for k in l_data.keys():
            all_keys[k] = 1
        keys = list(all_keys.keys())
        keys.sort()

        for key in keys:
            if key == "id":
                continue
            bv   = b_data.get(key, None)
            lv   = l_data.get(key, None)
            subp = "%s.%s" % (path, key)

            if bv is None and lv is not None:
                changes.append({"path": subp,
                                 "baseline_value": None,
                                 "live_value":     str(lv)[:200],
                                 "change_type":    "ADDED"})
            elif bv is not None and lv is None:
                changes.append({"path": subp,
                                 "baseline_value": str(bv)[:200],
                                 "live_value":     None,
                                 "change_type":    "REMOVED"})
            elif _is_str(bv) and _is_str(lv):
                if bv != lv:
                    sub = diff_attr_strings(bv, lv, subp)
                    if sub:
                        changes = changes + sub
                    else:
                        changes.append({"path": subp,
                                         "baseline_value": bv[:300],
                                         "live_value":     lv[:300],
                                         "change_type":    "MODIFIED"})
            else:
                changes = changes + diff_section(bv, lv, subp)

    elif _is_str(b_data) and _is_str(l_data):
        if b_data != l_data:
            sub = diff_attr_strings(b_data, l_data, path)
            if sub:
                changes = changes + sub
            else:
                changes.append({"path": path,
                                 "baseline_value": b_data[:300],
                                 "live_value":     l_data[:300],
                                 "change_type":    "MODIFIED"})
    else:
        if str(b_data) != str(l_data):
            changes.append({"path": path,
                             "baseline_value": str(b_data)[:300],
                             "live_value":     str(l_data)[:300],
                             "change_type":    "MODIFIED"})
    return changes


# =============================================================================
# REPORT BUILDER
# =============================================================================

def build_drift_report(baseline, live_snap):
    is_drifted = 0
    if baseline["composite_hash"] != live_snap["composite_hash"]:
        is_drifted = 1

    report = {
        "run_at":                time.strftime("%Y-%m-%dT%H:%M:%S"),
        "cell":                  live_snap["metadata"]["cell"],
        "baseline_timestamp":    baseline["metadata"]["timestamp"],
        "live_timestamp":        live_snap["metadata"]["timestamp"],
        "baseline_hash":         baseline["composite_hash"],
        "live_hash":             live_snap["composite_hash"],
        "drift_detected":        is_drifted,
        "section_summary":       {},
        "changes":               [],
        "total_changes":         0,
        "critical_change_count": 0,
        "severity":              "NONE",
    }

    if not is_drifted:
        log("No drift - composite hash unchanged.")
        return report

    b_hashes = baseline.get("hashes", {})
    l_hashes = live_snap.get("hashes", {})

    dirty = []
    for sec in b_hashes.keys():
        if b_hashes.get(sec) != l_hashes.get(sec):
            dirty.append(sec)
    for sec in l_hashes.keys():
        if sec not in b_hashes:
            dirty.append(sec)

    log("Dirty sections: %s" % str(dirty))

    all_changes     = []
    section_summary = {}
    b_secs = baseline.get("sections", {})
    l_secs = live_snap.get("sections", {})

    for sec in dirty:
        ch = diff_section(b_secs.get(sec, {}), l_secs.get(sec, {}), sec)
        section_summary[sec] = {"change_count": len(ch), "status": "DRIFTED"}
        all_changes = all_changes + ch

    for sec in b_hashes.keys():
        if sec not in dirty:
            section_summary[sec] = {"change_count": 0, "status": "OK"}

    # Count critical changes - no any() in Jython 2.1, use explicit loop
    critical_count = 0
    for ch in all_changes:
        path_lower = ch["path"].lower()
        for kw in CRITICAL_SECTIONS:
            if path_lower.find(kw) >= 0:
                critical_count += 1
                break

    n = len(all_changes)
    if critical_count > 0:
        severity = "CRITICAL"
    elif n > 20:
        severity = "HIGH"
    elif n > 5:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    report["section_summary"]       = section_summary
    report["changes"]               = all_changes
    report["total_changes"]         = n
    report["critical_change_count"] = critical_count
    report["severity"]              = severity
    return report


# =============================================================================
# EMAIL
# =============================================================================

def build_email_body(report):
    sep  = "=" * 70
    dash = "-" * 70
    lines = [
        sep,
        "  WebSphere Configuration Drift Alert",
        sep,
        "",
        "Cell            : %s" % report["cell"],
        "Detection Time  : %s" % report["run_at"],
        "Severity        : *** %s ***" % report["severity"],
        "Total Changes   : %d" % report["total_changes"],
        "Critical Changes: %d" % report["critical_change_count"],
        "",
        "Baseline taken  : %s" % report["baseline_timestamp"],
        "Live snapshot   : %s" % report["live_timestamp"],
        "Baseline hash   : %s" % report["baseline_hash"],
        "Live hash       : %s" % report["live_hash"],
        "",
        dash,
        "SECTION SUMMARY",
        dash,
    ]

    sec_keys = list(report["section_summary"].keys())
    sec_keys.sort()
    for sec in sec_keys:
        info = report["section_summary"][sec]
        if info["status"] == "DRIFTED":
            icon = "X"
        else:
            icon = "OK"
        lines.append("  [%s]  %-30s  %s  (%d changes)" % (
            icon, sec, info["status"], info["change_count"]))

    lines.append("")
    lines.append(dash)
    lines.append("DETAILED CHANGES")
    lines.append(dash)

    idx = 1
    for ch in report["changes"]:
        bv = ch.get("baseline_value")
        lv = ch.get("live_value")
        if bv is None:
            bv = "<null>"
        if lv is None:
            lv = "<null>"
        lines.append("")
        lines.append("[%d] PATH     : %s" % (idx, ch["path"]))
        lines.append("    TYPE     : %s" % ch["change_type"])
        lines.append("    BASELINE : %s" % str(bv)[:120])
        lines.append("    LIVE     : %s" % str(lv)[:120])
        idx += 1

    lines.append("")
    lines.append(dash)
    lines.append("ACTION REQUIRED")
    lines.append(dash)
    lines.append("1. Review changes above and confirm if authorised.")
    lines.append("2. If UNAUTHORISED - roll back via WAS Admin Console or wsadmin.")
    lines.append("3. If AUTHORISED   - refresh the baseline:")
    lines.append("   wsadmin.sh -lang jython -f %s/scripts/extract_baseline.py baseline" %
                 os.path.dirname(BASELINE_DIR))
    lines.append("4. Full JSON report saved to: %s" % REPORT_DIR)
    lines.append("")
    lines.append("Generated by WebSphere Drift Monitor.")
    lines.append(sep)
    return "\n".join(lines)


def send_email(report):
    subject  = "[%s] WebSphere Config Drift - %s - %s" % (
        report["severity"],
        report["cell"],
        report["run_at"].replace("T", " "))
    body     = build_email_body(report)
    mime_msg = "From: %s\r\nTo: %s\r\nSubject: %s\r\nX-Mailer: WebSphere-Drift-Monitor\r\n\r\n%s" % (
        EMAIL_FROM,
        ", ".join(EMAIL_TO),
        subject,
        body)
    try:
        srv = smtplib.SMTP(SMTP_HOST, 25)
        srv.ehlo()
        srv.sendmail(EMAIL_FROM, EMAIL_TO, mime_msg)
        srv.quit()
        log("Alert email sent via %s" % SMTP_HOST)
    except Exception, e:
        log("ERROR sending email: %s" % str(e))


# =============================================================================
# MAIN DRIFT CHECK
# =============================================================================

def run_drift_check():
    ensure_dir(REPORT_DIR)
    ensure_dir(SNAPSHOT_DIR)
    ensure_dir(os.path.dirname(LOG_FILE))

    baseline_path = os.path.join(BASELINE_DIR, "baseline.json")
    if not os.path.exists(baseline_path):
        log("ERROR: No baseline at %s - run extract_baseline.py first." % baseline_path)
        sys.exit(1)

    log("Loading baseline: %s" % baseline_path)
    baseline = read_json(baseline_path)

    if SCRIPTS_DIR not in sys.path:
        sys.path.insert(0, SCRIPTS_DIR)
    import extract_baseline as extractor

    log("Capturing live snapshot...")
    live_snap = extractor.build_snapshot()

    ts        = time.strftime("%Y%m%d_%H%M%S")
    snap_path = os.path.join(SNAPSHOT_DIR, "snapshot_%s.json" % ts)
    write_json(snap_path, live_snap)
    log("Snapshot saved: %s" % snap_path)

    report   = build_drift_report(baseline, live_snap)
    rpt_path = os.path.join(REPORT_DIR, "drift_report_%s.json" % ts)
    write_json(rpt_path, report)
    log("Report saved: %s" % rpt_path)

    if report["drift_detected"]:
        log("DRIFT DETECTED: %d changes, severity=%s" % (
            report["total_changes"], report["severity"]))
        send_email(report)
    else:
        log("Configuration matches baseline - no drift.")

    cleanup_old_files(SNAPSHOT_DIR, "snapshot_",     keep=72)
    cleanup_old_files(REPORT_DIR,   "drift_report_", keep=72)


# =============================================================================
# SCRIPT ENTRY POINT
# =============================================================================

try:
    if sys.argv[0].find("detect_drift") >= 0:
        run_drift_check()
except:
    pass
