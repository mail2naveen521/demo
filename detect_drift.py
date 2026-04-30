# =============================================================================
# WebSphere Configuration Drift Monitor - Drift Detector
# Compatible: WAS ND 8.5.5.27, Jython 2.7
# Run: wsadmin.sh -lang jython -f detect_drift.py
# =============================================================================

import os
import sys
import time
import re
import json
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

# Email - unauthenticated internal SMTP relay, port 25
SMTP_HOST     = "mailrelay.yourcompany.com"
EMAIL_FROM    = "was-monitor@yourcompany.com"
EMAIL_TO      = ["websphere-ops@yourcompany.com", "middleware-team@yourcompany.com"]

# Attributes excluded from comparison (transient/metadata)
IGNORED_ATTRS = {"lastModified", "modifiedBy", "deploymentDescriptorVersion"}

# Sections whose changes are classified CRITICAL
CRITICAL_SECTIONS = {"security", "ssl", "servers", "clusters", "datasources"}

# =============================================================================
# UTILITIES
# =============================================================================

def log(msg):
    ts   = time.strftime("%Y-%m-%d %H:%M:%S")
    line = "[{0}] {1}".format(ts, msg)
    print(line)
    try:
        with open(LOG_FILE, "a") as fh:
            fh.write(line + "\n")
    except Exception:
        pass


def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)


def sha256(s):
    md  = MessageDigest.getInstance("SHA-256")
    raw = md.digest(JString(s).getBytes("UTF-8"))
    return "".join("{0:02x}".format(b & 0xFF) for b in raw)


def write_json(path, data):
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)


def read_json(path):
    with open(path, "r") as fh:
        return json.load(fh)


def list_files(directory, prefix):
    """Return sorted list of filenames matching prefix."""
    if not os.path.exists(directory):
        return []
    return sorted(f for f in os.listdir(directory) if f.startswith(prefix))


def cleanup_old_files(directory, prefix, keep=72):
    for old in list_files(directory, prefix)[:-keep]:
        try:
            os.remove(os.path.join(directory, old))
        except Exception:
            pass


# =============================================================================
# DIFF ENGINE
# =============================================================================

def parse_was_attrs(attr_str):
    """Parse AdminConfig.show() output: [key value] [key value] ..."""
    attrs = {}
    for m in re.finditer(r"\[(\S+)\s+(.*?)\]", attr_str):
        key = m.group(1)
        if key not in IGNORED_ATTRS:
            attrs[key] = m.group(2).strip()
    return attrs


def diff_attr_strings(b_str, l_str, path):
    """Diff two AdminConfig attribute strings, return list of change dicts."""
    changes = []
    b_attrs = parse_was_attrs(b_str)
    l_attrs = parse_was_attrs(l_str)
    all_keys = sorted(set(b_attrs) | set(l_attrs))
    for key in all_keys:
        bv = b_attrs.get(key, "<MISSING>")
        lv = l_attrs.get(key, "<MISSING>")
        if bv != lv:
            changes.append({
                "path":           "{0}.{1}".format(path, key),
                "baseline_value": bv,
                "live_value":     lv,
                "change_type":    "ADDED"    if bv == "<MISSING>" else
                                  "REMOVED"  if lv == "<MISSING>" else
                                  "MODIFIED",
            })
    return changes


def diff_section(b_data, l_data, path):
    """Recursively diff two config section values."""
    changes = []

    if isinstance(b_data, dict) and isinstance(l_data, dict):
        all_keys = sorted(set(b_data) | set(l_data))
        for key in all_keys:
            if key == "id":
                continue
            bv   = b_data.get(key)
            lv   = l_data.get(key)
            subp = "{0}.{1}".format(path, key)
            if bv is None:
                changes.append({"path": subp, "baseline_value": None,
                                 "live_value": str(lv)[:200], "change_type": "ADDED"})
            elif lv is None:
                changes.append({"path": subp, "baseline_value": str(bv)[:200],
                                 "live_value": None, "change_type": "REMOVED"})
            elif isinstance(bv, str) and isinstance(lv, str):
                if bv != lv:
                    sub = diff_attr_strings(bv, lv, subp)
                    changes.extend(sub if sub else [{
                        "path": subp,
                        "baseline_value": bv[:300],
                        "live_value":     lv[:300],
                        "change_type":    "MODIFIED",
                    }])
            else:
                changes.extend(diff_section(bv, lv, subp))

    elif isinstance(b_data, str) and isinstance(l_data, str):
        if b_data != l_data:
            sub = diff_attr_strings(b_data, l_data, path)
            changes.extend(sub if sub else [{
                "path": path,
                "baseline_value": b_data[:300],
                "live_value":     l_data[:300],
                "change_type":    "MODIFIED",
            }])
    else:
        if str(b_data) != str(l_data):
            changes.append({
                "path":           path,
                "baseline_value": str(b_data)[:300],
                "live_value":     str(l_data)[:300],
                "change_type":    "MODIFIED",
            })
    return changes


# =============================================================================
# REPORT BUILDER
# =============================================================================

def build_drift_report(baseline, live_snap):
    """Compare baseline vs live snapshot and return structured report."""
    drifted = baseline["composite_hash"] != live_snap["composite_hash"]

    report = {
        "run_at":                time.strftime("%Y-%m-%dT%H:%M:%S"),
        "cell":                  live_snap["metadata"]["cell"],
        "baseline_timestamp":    baseline["metadata"]["timestamp"],
        "live_timestamp":        live_snap["metadata"]["timestamp"],
        "baseline_hash":         baseline["composite_hash"],
        "live_hash":             live_snap["composite_hash"],
        "drift_detected":        drifted,
        "section_summary":       {},
        "changes":               [],
        "total_changes":         0,
        "critical_change_count": 0,
        "severity":              "NONE",
    }

    if not drifted:
        log("No drift - composite hash unchanged.")
        return report

    b_hashes = baseline.get("hashes", {})
    l_hashes = live_snap.get("hashes", {})

    dirty = [sec for sec in b_hashes if b_hashes.get(sec) != l_hashes.get(sec)]
    dirty += [sec for sec in l_hashes if sec not in b_hashes]
    log("Dirty sections: {0}".format(dirty))

    all_changes     = []
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

    critical_count = sum(
        1 for ch in all_changes
        if any(kw in ch["path"].lower() for kw in CRITICAL_SECTIONS)
    )

    n = len(all_changes)
    severity = ("CRITICAL" if critical_count > 0 else
                "HIGH"     if n > 20             else
                "MEDIUM"   if n > 5              else
                "LOW")

    report.update({
        "section_summary":       section_summary,
        "changes":               all_changes,
        "total_changes":         n,
        "critical_change_count": critical_count,
        "severity":              severity,
    })
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
        sep, "",
        "Cell            : {0}".format(report["cell"]),
        "Detection Time  : {0}".format(report["run_at"]),
        "Severity        : *** {0} ***".format(report["severity"]),
        "Total Changes   : {0}".format(report["total_changes"]),
        "Critical Changes: {0}".format(report["critical_change_count"]),
        "",
        "Baseline taken  : {0}".format(report["baseline_timestamp"]),
        "Live snapshot   : {0}".format(report["live_timestamp"]),
        "Baseline hash   : {0}".format(report["baseline_hash"]),
        "Live hash       : {0}".format(report["live_hash"]),
        "", dash, "SECTION SUMMARY", dash,
    ]
    for sec in sorted(report["section_summary"]):
        info = report["section_summary"][sec]
        icon = "X" if info["status"] == "DRIFTED" else "OK"
        lines.append("  [{0}]  {1:<30}  {2}  ({3} changes)".format(
            icon, sec, info["status"], info["change_count"]))

    lines += ["", dash, "DETAILED CHANGES", dash]
    for idx, ch in enumerate(report["changes"], 1):
        bv = ch.get("baseline_value") or "<null>"
        lv = ch.get("live_value")     or "<null>"
        lines += [
            "",
            "[{0}] PATH     : {1}".format(idx, ch["path"]),
            "    TYPE     : {0}".format(ch["change_type"]),
            "    BASELINE : {0}".format(str(bv)[:120]),
            "    LIVE     : {0}".format(str(lv)[:120]),
        ]

    lines += [
        "", dash, "ACTION REQUIRED", dash,
        "1. Review the changes above and confirm if they are authorised.",
        "2. If UNAUTHORISED - roll back via WAS Admin Console or wsadmin.",
        "3. If AUTHORISED   - refresh the baseline:",
        "   wsadmin.sh -lang jython -f {0}/scripts/extract_baseline.py baseline".format(
            os.path.dirname(BASELINE_DIR)),
        "4. Full JSON report saved to: {0}".format(REPORT_DIR),
        "", "Generated by WebSphere Drift Monitor.", sep,
    ]
    return "\n".join(lines)


def send_email(report):
    """Send alert via unauthenticated internal SMTP relay on port 25."""
    subject  = "[{sev}] WebSphere Config Drift - {cell} - {ts}".format(
        sev=report["severity"],
        cell=report["cell"],
        ts=report["run_at"].replace("T", " "))
    body     = build_email_body(report)
    mime_msg = (
        "From: {frm}\r\n"
        "To: {to}\r\n"
        "Subject: {sub}\r\n"
        "X-Mailer: WebSphere-Drift-Monitor\r\n"
        "\r\n"
        "{body}"
    ).format(
        frm=EMAIL_FROM,
        to=", ".join(EMAIL_TO),
        sub=subject,
        body=body,
    )
    try:
        srv = smtplib.SMTP(SMTP_HOST, 25)
        srv.ehlo()
        srv.sendmail(EMAIL_FROM, EMAIL_TO, mime_msg)
        srv.quit()
        log("Alert email sent via {0}".format(SMTP_HOST))
    except Exception as e:
        log("ERROR sending email via {0}: {1}".format(SMTP_HOST, str(e)))


# =============================================================================
# MAIN DRIFT CHECK
# =============================================================================

def run_drift_check():
    ensure_dir(REPORT_DIR)
    ensure_dir(SNAPSHOT_DIR)
    ensure_dir(os.path.dirname(LOG_FILE))

    baseline_path = os.path.join(BASELINE_DIR, "baseline.json")
    if not os.path.exists(baseline_path):
        log("ERROR: No baseline at {0} - run extract_baseline.py first.".format(baseline_path))
        sys.exit(1)

    log("Loading baseline: {0}".format(baseline_path))
    baseline = read_json(baseline_path)

    if SCRIPTS_DIR not in sys.path:
        sys.path.insert(0, SCRIPTS_DIR)
    import extract_baseline as extractor

    log("Capturing live snapshot...")
    live_snap = extractor.build_snapshot()

    ts        = time.strftime("%Y%m%d_%H%M%S")
    snap_path = os.path.join(SNAPSHOT_DIR, "snapshot_{0}.json".format(ts))
    write_json(snap_path, live_snap)
    log("Snapshot saved: {0}".format(snap_path))

    report   = build_drift_report(baseline, live_snap)
    rpt_path = os.path.join(REPORT_DIR, "drift_report_{0}.json".format(ts))
    write_json(rpt_path, report)
    log("Report saved: {0}".format(rpt_path))

    if report["drift_detected"]:
        log("DRIFT DETECTED: {0} changes, severity={1}".format(
            report["total_changes"], report["severity"]))
        send_email(report)
    else:
        log("Configuration matches baseline - no drift.")

    cleanup_old_files(SNAPSHOT_DIR, "snapshot_",     keep=72)
    cleanup_old_files(REPORT_DIR,   "drift_report_", keep=72)


# =============================================================================
# ENTRY
# =============================================================================
try:
    if "detect_drift" in sys.argv[0]:
        run_drift_check()
except (IndexError, TypeError):
    pass
