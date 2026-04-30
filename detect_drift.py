"""
WebSphere Configuration Drift Detector
Tested against WAS ND 8.5.5 embedded Jython 2.1.
- No hashlib  -> java.security.MessageDigest
- No json     -> hand-rolled serialiser / parser
- No sorted() -> list.sort()
- No enumerate() -> index counter
- No any()    -> explicit loop
- No ternary (x if c else y) -> explicit if/else blocks
- No generator expressions -> list comprehensions or loops

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
# HELPERS  – Jython 2.1 safe
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


def sorted_list(lst):
    """Return a new sorted list. Replaces sorted() builtin (Python 2.4+)."""
    copy = lst[:]
    copy.sort()
    return copy


# ── SHA-256 via Java MessageDigest ───────────────────────────────────────────

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


# ── JSON serialiser ───────────────────────────────────────────────────────────

def _escape(s):
    s = str(s)
    s = s.replace("\\", "\\\\")
    s = s.replace('"',  '\\"')
    s = s.replace("\n", "\\n")
    s = s.replace("\r", "\\r")
    s = s.replace("\t", "\\t")
    return s


def to_json(obj, ind=0):
    sp  = " " * ind
    sp2 = " " * (ind + 2)

    if obj is None:
        return "null"

    if isinstance(obj, bool):
        if obj:
            return "true"
        else:
            return "false"

    if isinstance(obj, int) or isinstance(obj, float):
        return str(obj)

    try:
        if isinstance(obj, long):
            return str(obj)
    except NameError:
        pass

    if isinstance(obj, str) or isinstance(obj, unicode):
        return '"' + _escape(obj) + '"'

    if isinstance(obj, list) or isinstance(obj, tuple):
        if not obj:
            return "[]"
        parts = []
        for v in obj:
            parts.append(sp2 + to_json(v, ind + 2))
        return "[\n" + ",\n".join(parts) + "\n" + sp + "]"

    if isinstance(obj, dict):
        if not obj:
            return "{}"
        keys = obj.keys()
        keys.sort()
        parts = []
        for k in keys:
            parts.append(sp2 + '"' + _escape(str(k)) + '": ' + to_json(obj[k], ind + 2))
        return "{\n" + ",\n".join(parts) + "\n" + sp + "}"

    return '"' + _escape(str(obj)) + '"'


# ── JSON parser ───────────────────────────────────────────────────────────────

def _skip_ws(s, p):
    while p < len(s) and s[p] in " \t\n\r":
        p += 1
    return p


def _parse(s, p):
    p = _skip_ws(s, p)
    c = s[p]

    if c == '"':
        p += 1
        buf = []
        esc_map = {"n": "\n", "r": "\r", "t": "\t",
                   '"': '"', "\\": "\\", "/": "/"}
        while p < len(s):
            ch = s[p]
            if ch == '"':
                return "".join(buf), p + 1
            if ch == '\\':
                p += 1
                mapped = esc_map.get(s[p], s[p])
                buf.append(mapped)
            else:
                buf.append(ch)
            p += 1
        raise ValueError("Unterminated string")

    if c == '{':
        p += 1
        obj = {}
        while 1:
            p = _skip_ws(s, p)
            if s[p] == '}':
                return obj, p + 1
            if s[p] == ',':
                p += 1
                continue
            k, p = _parse(s, p)
            p = _skip_ws(s, p)
            p += 1
            v, p = _parse(s, p)
            obj[k] = v

    if c == '[':
        p += 1
        arr = []
        while 1:
            p = _skip_ws(s, p)
            if s[p] == ']':
                return arr, p + 1
            if s[p] == ',':
                p += 1
                continue
            v, p = _parse(s, p)
            arr.append(v)

    if s[p:p+4] == "null":
        return None, p + 4
    if s[p:p+4] == "true":
        return 1, p + 4
    if s[p:p+5] == "false":
        return 0, p + 5

    end = p
    while end < len(s) and s[end] not in " \t\n\r,}]":
        end += 1
    tok = s[p:end]
    try:
        return int(tok), end
    except ValueError:
        return float(tok), end


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


# ── File listing (replaces glob) ─────────────────────────────────────────────

def list_files(directory, prefix):
    """Return sorted list of filenames in directory starting with prefix."""
    if not os.path.exists(directory):
        return []
    results = []
    for fname in os.listdir(directory):
        if fname[:len(prefix)] == prefix:
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
    key_lower = key.lower()
    for ig in IGNORED_ATTRS:
        if ig.lower() in key_lower:
            return 1
    return 0


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
    for k in b_attrs.keys():
        all_keys[k] = 1
    for k in l_attrs.keys():
        all_keys[k] = 1

    keys = all_keys.keys()
    keys.sort()
    for key in keys:
        b_val = b_attrs.get(key, "<MISSING>")
        l_val = l_attrs.get(key, "<MISSING>")
        if b_val != l_val:
            if b_val == "<MISSING>":
                ctype = "ADDED"
            elif l_val == "<MISSING>":
                ctype = "REMOVED"
            else:
                ctype = "MODIFIED"
            changes.append({"path":           "%s.%s" % (path, key),
                             "baseline_value": b_val,
                             "live_value":     l_val,
                             "change_type":    ctype})
    return changes


def diff_section(b_data, l_data, path):
    changes = []

    if isinstance(b_data, dict) and isinstance(l_data, dict):
        all_keys = {}
        for k in b_data.keys():
            all_keys[k] = 1
        for k in l_data.keys():
            all_keys[k] = 1

        keys = all_keys.keys()
        keys.sort()
        for key in keys:
            if key == "id":
                continue
            b_val = b_data.get(key, None)
            l_val = l_data.get(key, None)
            subp  = "%s.%s" % (path, key)

            if b_val is None and l_val is not None:
                changes.append({"path":           subp,
                                 "baseline_value": None,
                                 "live_value":     str(l_val)[:200],
                                 "change_type":    "ADDED"})
            elif b_val is not None and l_val is None:
                changes.append({"path":           subp,
                                 "baseline_value": str(b_val)[:200],
                                 "live_value":     None,
                                 "change_type":    "REMOVED"})
            elif (isinstance(b_val, str) or isinstance(b_val, unicode)) and \
                 (isinstance(l_val, str) or isinstance(l_val, unicode)):
                if b_val != l_val:
                    sub = diff_attr_strings(b_val, l_val, subp)
                    if sub:
                        changes = changes + sub
                    else:
                        changes.append({"path":           subp,
                                         "baseline_value": str(b_val)[:300],
                                         "live_value":     str(l_val)[:300],
                                         "change_type":    "MODIFIED"})
            else:
                sub = diff_section(b_val, l_val, subp)
                changes = changes + sub

    elif (isinstance(b_data, str) or isinstance(b_data, unicode)) and \
         (isinstance(l_data, str) or isinstance(l_data, unicode)):
        if b_data != l_data:
            sub = diff_attr_strings(b_data, l_data, path)
            if sub:
                changes = changes + sub
            else:
                changes.append({"path":           path,
                                 "baseline_value": str(b_data)[:300],
                                 "live_value":     str(l_data)[:300],
                                 "change_type":    "MODIFIED"})
    else:
        if str(b_data) != str(l_data):
            changes.append({"path":           path,
                             "baseline_value": str(b_data)[:300],
                             "live_value":     str(l_data)[:300],
                             "change_type":    "MODIFIED"})
    return changes


# ─────────────────────────────────────────────
# REPORT BUILDER
# ─────────────────────────────────────────────

def build_drift_report(baseline, live_snap):
    is_drifted = 0
    if baseline["composite_hash"] != live_snap["composite_hash"]:
        is_drifted = 1

    report = {
        "run_at"               : time.strftime("%Y-%m-%dT%H:%M:%S"),
        "cell"                 : live_snap["metadata"]["cell"],
        "baseline_timestamp"   : baseline["metadata"]["timestamp"],
        "live_timestamp"       : live_snap["metadata"]["timestamp"],
        "baseline_hash"        : baseline["composite_hash"],
        "live_hash"            : live_snap["composite_hash"],
        "drift_detected"       : is_drifted,
        "section_summary"      : {},
        "changes"              : [],
        "total_changes"        : 0,
        "critical_change_count": 0,
        "severity"             : "NONE",
    }

    if not is_drifted:
        log("No drift detected – composite hash unchanged.")
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

    all_changes    = []
    section_summary = {}
    b_secs = baseline.get("sections", {})
    l_secs = live_snap.get("sections", {})

    for sec in dirty:
        b_sec = b_secs.get(sec, {})
        l_sec = l_secs.get(sec, {})
        ch    = diff_section(b_sec, l_sec, sec)
        section_summary[sec] = {"change_count": len(ch), "status": "DRIFTED"}
        all_changes = all_changes + ch

    for sec in b_hashes.keys():
        if sec not in dirty:
            section_summary[sec] = {"change_count": 0, "status": "OK"}

    # Count critical changes without any() or list comprehension with condition
    critical_kw      = ["security", "ssl", "jvm", "datasource", "cluster"]
    critical_count   = 0
    for ch in all_changes:
        path_lower = ch["path"].lower()
        for kw in critical_kw:
            if kw in path_lower:
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

    sec_keys = report["section_summary"].keys()
    sec_keys.sort()
    for sec in sec_keys:
        info = report["section_summary"][sec]
        if info["status"] == "DRIFTED":
            icon = "X"
        else:
            icon = "OK"
        lines.append("  [%s]  %-30s  %s (%d changes)" % (
            icon, sec, info["status"], info["change_count"]))

    lines.append("")
    lines.append("-" * 70)
    lines.append("DETAILED CHANGES")
    lines.append("-" * 70)

    # replaces enumerate()
    idx = 1
    for ch in report["changes"]:
        lines.append("")
        lines.append("[%d] PATH     : %s" % (idx, ch["path"]))
        lines.append("    TYPE     : %s" % ch["change_type"])
        bv = ch.get("baseline_value")
        lv = ch.get("live_value")
        if bv is None:
            bv = "<null>"
        if lv is None:
            lv = "<null>"
        lines.append("    BASELINE : %s" % str(bv)[:120])
        lines.append("    LIVE     : %s" % str(lv)[:120])
        idx += 1

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
        report["severity"],
        report["cell"],
        report["run_at"].replace("T", " "))
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
    except Exception, e:
        log("ERROR: Failed to send email via %s:25 - %s" % (SMTP_HOST, str(e)))


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

    cleanup_old_files(SNAPSHOT_DIR, "snapshot_",     keep=72)
    cleanup_old_files(REPORT_DIR,   "drift_report_", keep=72)


if __name__ == "__main__" or 1:
    run_drift_check()
