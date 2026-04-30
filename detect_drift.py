"""
WebSphere Configuration Drift Detector
Compatible with WAS embedded Jython 2.1 / 2.2 (no hashlib, no json, no glob).

Run via: wsadmin.sh -lang jython -f detect_drift.py
"""

import os
import sys
import time
import re
import smtplib

from java.security import MessageDigest
from java.lang     import String as JString

# ─────────────────────────────────────────────
# CONFIGURATION  – edit before deployment
# ─────────────────────────────────────────────
BASELINE_DIR  = "/opt/drift-monitor/baseline"
SNAPSHOT_DIR  = "/opt/drift-monitor/snapshots"
REPORT_DIR    = "/opt/drift-monitor/reports"
LOG_FILE      = "/opt/drift-monitor/logs/drift.log"

# Email – unauthenticated internal relay on port 25, no password needed
SMTP_HOST     = "mailrelay.yourcompany.com"
EMAIL_FROM    = "was-monitor@yourcompany.com"
EMAIL_TO      = ["websphere-ops@yourcompany.com", "middleware-team@yourcompany.com"]

IGNORED_ATTRS = ["lastModified", "modifiedBy", "deploymentDescriptorVersion"]

# ─────────────────────────────────────────────
# JYTHON 2.1-SAFE HELPERS  (same as extract_baseline.py)
# ─────────────────────────────────────────────

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


def sha256_str(s):
    md     = MessageDigest.getInstance("SHA-256")
    raw    = md.digest(JString(s).getBytes("UTF-8"))
    hexc   = "0123456789abcdef"
    result = []
    for b in raw:
        ub = b & 0xFF
        result.append(hexc[ub >> 4])
        result.append(hexc[ub & 0x0F])
    return "".join(result)


def _escape(s):
    s = s.replace("\\", "\\\\")
    s = s.replace('"',  '\\"')
    s = s.replace("\n", "\\n")
    s = s.replace("\r", "\\r")
    s = s.replace("\t", "\\t")
    return s


def to_json(obj, ind=0):
    sp  = " " * ind
    sp2 = " " * (ind + 2)
    if obj is None:                             return "null"
    if isinstance(obj, bool):                   return "true" if obj else "false"
    if isinstance(obj, (int, long, float)):     return str(obj)
    if isinstance(obj, (str, unicode)):         return '"' + _escape(str(obj)) + '"'
    if isinstance(obj, (list, tuple)):
        if not obj: return "[]"
        return "[\n" + ",\n".join([sp2 + to_json(v, ind + 2) for v in obj]) + "\n" + sp + "]"
    if isinstance(obj, dict):
        if not obj: return "{}"
        keys = sorted(obj.keys())
        return "{\n" + ",\n".join(
            [sp2 + '"' + _escape(str(k)) + '": ' + to_json(obj[k], ind + 2) for k in keys]
        ) + "\n" + sp + "}"
    return '"' + _escape(str(obj)) + '"'


def _skip_ws(s, p):
    while p < len(s) and s[p] in " \t\n\r": p += 1
    return p


def _parse(s, p):
    p = _skip_ws(s, p)
    c = s[p]
    if c == '"':
        p += 1; buf = []
        while p < len(s):
            ch = s[p]
            if ch == '"':  return "".join(buf), p + 1
            if ch == '\\':
                p += 1
                buf.append({"n":"\n","r":"\r","t":"\t",'"':'"',"\\":"\\","/":" "}.get(s[p], s[p]))
            else: buf.append(ch)
            p += 1
        raise ValueError("Unterminated string")
    if c == '{':
        p += 1; obj = {}
        while True:
            p = _skip_ws(s, p)
            if s[p] == '}': return obj, p + 1
            if s[p] == ',': p += 1; continue
            k, p = _parse(s, p); p = _skip_ws(s, p); p += 1
            v, p = _parse(s, p); obj[k] = v
    if c == '[':
        p += 1; arr = []
        while True:
            p = _skip_ws(s, p)
            if s[p] == ']': return arr, p + 1
            if s[p] == ',': p += 1; continue
            v, p = _parse(s, p); arr.append(v)
    if s[p:p+4] == "null":  return None,  p + 4
    if s[p:p+4] == "true":  return True,  p + 4
    if s[p:p+5] == "false": return False, p + 5
    end = p
    while end < len(s) and s[end] not in " \t\n\r,}]": end += 1
    tok = s[p:end]
    try:    return int(tok),   end
    except: return float(tok), end


def from_json(s):
    val, _ = _parse(s, 0)
    return val


def read_json_file(path):
    fh   = open(path, "r")
    text = fh.read()
    fh.close()
    return from_json(text)


def write_json_file(path, data):
    fh = open(path, "w")
    fh.write(to_json(data))
    fh.close()


# ── glob replacement (no glob module) ────────────────────────────────────────

def list_files(directory, prefix):
    """Return sorted list of filenames in directory starting with prefix."""
    if not os.path.exists(directory):
        return []
    results = []
    for fname in os.listdir(directory):
        if fname.startswith(prefix):
            results.append(fname)
    results.sort()
    return results


def cleanup_old_files(directory, prefix, keep=72):
    files = list_files(directory, prefix)
    for old in files[:-keep]:
        try:
            os.remove(os.path.join(directory, old))
        except:
            pass


# ─────────────────────────────────────────────
# DEEP DIFF ENGINE
# ─────────────────────────────────────────────

def is_ignored(key):
    for ig in IGNORED_ATTRS:
        if ig.lower() in key.lower():
            return True
    return False


def parse_was_attrs(attr_str):
    """Parse WAS AdminConfig.show() output: [key value] [key value] ..."""
    attrs = {}
    for m in re.finditer(r"\[(\S+)\s+(.*?)\]", attr_str):
        key = m.group(1)
        val = m.group(2).strip()
        if not is_ignored(key):
            attrs[key] = val
    return attrs


def diff_attr_strings(b_str, l_str, path):
    changes = []
    b_attrs = parse_was_attrs(b_str)
    l_attrs = parse_was_attrs(l_str)
    all_keys = {}
    for k in b_attrs: all_keys[k] = 1
    for k in l_attrs: all_keys[k] = 1
    for key in sorted(all_keys.keys()):
        bv = b_attrs.get(key, "<MISSING>")
        lv = l_attrs.get(key, "<MISSING>")
        if bv != lv:
            if bv == "<MISSING>":   ctype = "ADDED"
            elif lv == "<MISSING>": ctype = "REMOVED"
            else:                   ctype = "MODIFIED"
            changes.append({"path": "%s.%s" % (path, key),
                             "baseline_value": bv,
                             "live_value"    : lv,
                             "change_type"   : ctype})
    return changes


def diff_section(b_data, l_data, path):
    changes = []
    if isinstance(b_data, dict) and isinstance(l_data, dict):
        all_keys = {}
        for k in b_data: all_keys[k] = 1
        for k in l_data: all_keys[k] = 1
        for key in sorted(all_keys.keys()):
            if key == "id": continue
            bv   = b_data.get(key)
            lv   = l_data.get(key)
            subp = "%s.%s" % (path, key)
            if bv is None and lv is not None:
                changes.append({"path": subp, "baseline_value": None,
                                 "live_value": str(lv)[:200], "change_type": "ADDED"})
            elif bv is not None and lv is None:
                changes.append({"path": subp, "baseline_value": str(bv)[:200],
                                 "live_value": None, "change_type": "REMOVED"})
            elif isinstance(bv, (str, unicode)) and isinstance(lv, (str, unicode)):
                if bv != lv:
                    sub = diff_attr_strings(bv, lv, subp)
                    if sub:
                        changes.extend(sub)
                    else:
                        changes.append({"path": subp,
                                         "baseline_value": str(bv)[:300],
                                         "live_value"    : str(lv)[:300],
                                         "change_type"   : "MODIFIED"})
            else:
                changes.extend(diff_section(bv, lv, subp))
    elif isinstance(b_data, (str, unicode)) and isinstance(l_data, (str, unicode)):
        if b_data != l_data:
            sub = diff_attr_strings(b_data, l_data, path)
            if sub:
                changes.extend(sub)
            else:
                changes.append({"path": path,
                                 "baseline_value": str(b_data)[:300],
                                 "live_value"    : str(l_data)[:300],
                                 "change_type"   : "MODIFIED"})
    else:
        if str(b_data) != str(l_data):
            changes.append({"path": path,
                             "baseline_value": str(b_data)[:300],
                             "live_value"    : str(l_data)[:300],
                             "change_type"   : "MODIFIED"})
    return changes


# ─────────────────────────────────────────────
# REPORT BUILDER
# ─────────────────────────────────────────────

def build_drift_report(baseline, live_snap):
    report = {
        "run_at"            : time.strftime("%Y-%m-%dT%H:%M:%S"),
        "cell"              : live_snap["metadata"]["cell"],
        "baseline_timestamp": baseline["metadata"]["timestamp"],
        "live_timestamp"    : live_snap["metadata"]["timestamp"],
        "baseline_hash"     : baseline["composite_hash"],
        "live_hash"         : live_snap["composite_hash"],
        "drift_detected"    : baseline["composite_hash"] != live_snap["composite_hash"],
        "section_summary"   : {},
        "changes"           : [],
        "total_changes"     : 0,
        "critical_change_count": 0,
        "severity"          : "NONE",
    }

    if not report["drift_detected"]:
        log("No drift detected – composite hash unchanged.")
        return report

    b_hashes = baseline.get("hashes", {})
    l_hashes = live_snap.get("hashes", {})
    dirty    = []
    for sec in b_hashes:
        if b_hashes.get(sec) != l_hashes.get(sec):
            dirty.append(sec)
    for sec in l_hashes:
        if sec not in b_hashes:
            dirty.append(sec)

    log("Dirty sections: %s" % str(dirty))

    all_changes    = []
    section_summary = {}
    b_secs = baseline.get("sections", {})
    l_secs = live_snap.get("sections", {})

    for sec in dirty:
        ch = diff_section(b_secs.get(sec, {}), l_secs.get(sec, {}), sec)
        section_summary[sec] = {"change_count": len(ch), "status": "DRIFTED"}
        all_changes.extend(ch)

    for sec in b_hashes:
        if sec not in dirty:
            section_summary[sec] = {"change_count": 0, "status": "OK"}

    critical_kw = ["security", "ssl", "jvm", "datasource", "cluster"]
    critical    = [c for c in all_changes
                   if any(kw in c["path"].lower() for kw in critical_kw)]

    report["section_summary"]      = section_summary
    report["changes"]              = all_changes
    report["total_changes"]        = len(all_changes)
    report["critical_change_count"]= len(critical)
    report["severity"] = (
        "CRITICAL" if critical        else
        "HIGH"     if len(all_changes) > 20 else
        "MEDIUM"   if len(all_changes) > 5  else
        "LOW"
    )
    return report


# ─────────────────────────────────────────────
# EMAIL
# ─────────────────────────────────────────────

def build_email_body(report):
    lines = []
    lines.append("=" * 70)
    lines.append("  WebSphere Configuration Drift Alert")
    lines.append("=" * 70)
    lines.append("")
    lines.append("Cell            : %s" % report["cell"])
    lines.append("Detection Time  : %s" % report["run_at"])
    lines.append("Severity        : *** %s ***" % report["severity"])
    lines.append("Total Changes   : %d" % report["total_changes"])
    lines.append("Critical Changes: %d" % report["critical_change_count"])
    lines.append("")
    lines.append("Baseline taken  : %s" % report["baseline_timestamp"])
    lines.append("Live snapshot   : %s" % report["live_timestamp"])
    lines.append("Baseline hash   : %s" % report["baseline_hash"])
    lines.append("Live hash       : %s" % report["live_hash"])
    lines.append("")
    lines.append("-" * 70)
    lines.append("SECTION SUMMARY")
    lines.append("-" * 70)
    for sec in sorted(report["section_summary"].keys()):
        info = report["section_summary"][sec]
        icon = "X" if info["status"] == "DRIFTED" else "OK"
        lines.append("  [%s]  %-30s  %s (%d changes)" % (
            icon, sec, info["status"], info["change_count"]))
    lines.append("")
    lines.append("-" * 70)
    lines.append("DETAILED CHANGES")
    lines.append("-" * 70)
    for i, ch in enumerate(report["changes"], 1):
        lines.append("")
        lines.append("[%d] PATH     : %s" % (i, ch["path"]))
        lines.append("    TYPE     : %s" % ch["change_type"])
        lines.append("    BASELINE : %s" % str(ch.get("baseline_value") or "<null>")[:120])
        lines.append("    LIVE     : %s" % str(ch.get("live_value")     or "<null>")[:120])
    lines.append("")
    lines.append("-" * 70)
    lines.append("ACTION REQUIRED")
    lines.append("-" * 70)
    lines.append("1. Review changes above and verify they are authorised.")
    lines.append("2. If unauthorised, roll back via WAS admin console or wsadmin.")
    lines.append("3. If authorised, refresh the baseline:")
    lines.append("   wsadmin.sh -lang jython -f extract_baseline.py baseline")
    lines.append("4. Full JSON report saved to: %s" % REPORT_DIR)
    lines.append("")
    lines.append("This alert was generated by the WebSphere Drift Monitor.")
    lines.append("=" * 70)
    return "\n".join(lines)


def send_email(report):
    """
    Send alert via unauthenticated internal SMTP relay (port 25).
    No credentials or TLS – relies on relay whitelisting the DMGR host IP.
    """
    subject  = "[%s] WebSphere Config Drift Detected - %s - %s" % (
        report["severity"], report["cell"], report["run_at"].replace("T", " "))
    body     = build_email_body(report)
    mime_msg = (
        "From: %s\r\n"
        "To: %s\r\n"
        "Subject: %s\r\n"
        "X-Mailer: WebSphere-Drift-Monitor\r\n"
        "\r\n"
        "%s"
    ) % (EMAIL_FROM, ", ".join(EMAIL_TO), subject, body)

    try:
        server = smtplib.SMTP(SMTP_HOST, 25)
        server.ehlo()
        server.sendmail(EMAIL_FROM, EMAIL_TO, mime_msg)
        server.quit()
        log("Alert email sent via %s to: %s" % (SMTP_HOST, str(EMAIL_TO)))
    except Exception as e:
        log("ERROR: Failed to send email via %s:25 – %s" % (SMTP_HOST, str(e)))


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def run_drift_check():
    ensure_dir(REPORT_DIR)
    ensure_dir(SNAPSHOT_DIR)
    ensure_dir(os.path.dirname(LOG_FILE))

    baseline_path = os.path.join(BASELINE_DIR, "baseline.json")
    if not os.path.exists(baseline_path):
        log("ERROR: No baseline found at %s. Run extract_baseline.py first." % baseline_path)
        sys.exit(1)

    log("Loading baseline from: %s" % baseline_path)
    baseline = read_json_file(baseline_path)

    log("Capturing live configuration snapshot...")
    # Import extraction functions directly from same directory
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import extract_baseline as extractor
    live_snap = extractor.build_snapshot()

    ts        = time.strftime("%Y%m%d_%H%M%S")
    snap_path = os.path.join(SNAPSHOT_DIR, "snapshot_%s.json" % ts)
    write_json_file(snap_path, live_snap)
    log("Live snapshot saved: %s" % snap_path)

    report   = build_drift_report(baseline, live_snap)
    rpt_path = os.path.join(REPORT_DIR, "drift_report_%s.json" % ts)
    write_json_file(rpt_path, report)
    log("Report saved: %s" % rpt_path)

    if report["drift_detected"]:
        log("DRIFT DETECTED! %d changes. Severity: %s" % (
            report["total_changes"], report["severity"]))
        send_email(report)
    else:
        log("No drift detected. Configuration matches baseline.")

    cleanup_old_files(SNAPSHOT_DIR, "snapshot_",    keep=72)
    cleanup_old_files(REPORT_DIR,   "drift_report_", keep=72)


if __name__ == "__main__" or True:
    run_drift_check()
