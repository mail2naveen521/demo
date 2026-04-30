"""
WebSphere Drift Monitor – Report Viewer & Baseline Manager
Compatible with WAS embedded Jython 2.1 / 2.2 (no json, no glob).

Usage:
  wsadmin.sh -lang jython -f manage_drift.py [command]

Commands:
  status          - Show latest drift check result
  history [N]     - Show last N drift reports (default 10)
  update-baseline - Capture fresh baseline after approved changes
  compare [file]  - Compare live config against a specific snapshot file
"""

import os
import sys
import time

# ─────────────────────────────────────────────
MONITOR_HOME = "/opt/drift-monitor"
BASELINE_DIR = os.path.join(MONITOR_HOME, "baseline")
SNAPSHOT_DIR = os.path.join(MONITOR_HOME, "snapshots")
REPORT_DIR   = os.path.join(MONITOR_HOME, "reports")
SCRIPTS_DIR  = os.path.join(MONITOR_HOME, "scripts")


# ── Reuse helpers from detect_drift ──────────────────────────────────────────

sys.path.insert(0, SCRIPTS_DIR)
import extract_baseline as extractor
import detect_drift     as detector


def list_files(directory, prefix):
    if not os.path.exists(directory):
        return []
    results = [f for f in os.listdir(directory) if f.startswith(prefix)]
    results.sort()
    return results


def hr(ch="-", w=70):
    print ch * w


# ─────────────────────────────────────────────
# COMMANDS
# ─────────────────────────────────────────────

def print_status():
    files = list_files(REPORT_DIR, "drift_report_")
    if not files:
        print "No drift reports found. Has the monitor run yet?"
        return

    rpt = extractor.read_json_file(os.path.join(REPORT_DIR, files[-1]))

    hr("=")
    print "  WebSphere Drift Monitor -- Status"
    hr("=")
    print "Cell            : %s" % rpt.get("cell", "unknown")
    print "Last Check      : %s" % rpt.get("run_at", "unknown")
    print "Baseline From   : %s" % rpt.get("baseline_timestamp", "unknown")

    if rpt.get("drift_detected"):
        print "Status          : *** DRIFT DETECTED ***"
        print "Severity        : %s"  % rpt.get("severity", "UNKNOWN")
        print "Total Changes   : %d"  % rpt.get("total_changes", 0)
        print "Critical Changes: %d"  % rpt.get("critical_change_count", 0)
        print ""
        hr()
        print "SECTION SUMMARY"
        hr()
        for sec in sorted(rpt.get("section_summary", {}).keys()):
            info = rpt["section_summary"][sec]
            icon = "X" if info["status"] == "DRIFTED" else "OK"
            print "  [%s]  %-30s  %s (%d)" % (icon, sec, info["status"], info["change_count"])
        print ""
        print "Report file: %s" % os.path.join(REPORT_DIR, files[-1])
    else:
        print "Status          : CLEAN -- No drift detected"
    hr("=")


def print_history(n=10):
    files = list_files(REPORT_DIR, "drift_report_")[-n:]
    hr("=")
    print "  Drift Check History (last %d)" % n
    hr("=")
    print "  %-22s  %-10s  %-8s  %s" % ("RUN_AT", "STATUS", "CHANGES", "SEVERITY")
    hr()
    for fname in reversed(files):
        try:
            r        = extractor.read_json_file(os.path.join(REPORT_DIR, fname))
            status   = "DRIFTED" if r.get("drift_detected") else "CLEAN"
            changes  = r.get("total_changes", 0)
            severity = r.get("severity", "-") if r.get("drift_detected") else "-"
            print "  %-22s  %-10s  %-8s  %s" % (r.get("run_at","?"), status, changes, severity)
        except Exception as e:
            print "  [error reading %s: %s]" % (fname, str(e))
    hr("=")


def update_baseline():
    hr("=")
    print "  Updating WebSphere Config Baseline"
    hr("=")
    print "Capturing configuration from DMGR..."
    snap = extractor.build_snapshot()

    old_path = os.path.join(BASELINE_DIR, "baseline.json")
    if os.path.exists(old_path):
        ts      = time.strftime("%Y%m%d_%H%M%S")
        arch_dir = os.path.join(BASELINE_DIR, "archive")
        if not os.path.exists(arch_dir):
            os.makedirs(arch_dir)
        arch_path = os.path.join(arch_dir, "baseline_%s.json" % ts)
        fh_r = open(old_path, "r")
        old_content = fh_r.read()
        fh_r.close()
        fh_w = open(arch_path, "w")
        fh_w.write(old_content)
        fh_w.close()
        print "Previous baseline archived to: %s" % arch_path

    extractor.write_json_file(old_path, snap)
    print "New baseline saved   : %s" % old_path
    print "Composite hash       : %s" % snap["composite_hash"]
    print "Timestamp            : %s" % snap["metadata"]["timestamp"]
    hr("=")


def compare_specific(snapshot_file=None):
    ref_path = snapshot_file if snapshot_file else os.path.join(BASELINE_DIR, "baseline.json")
    print "Loading reference : %s" % ref_path
    reference = extractor.read_json_file(ref_path)

    print "Capturing live configuration..."
    live_snap = extractor.build_snapshot()

    report = detector.build_drift_report(reference, live_snap)

    if report["drift_detected"]:
        print "\n*** %d changes found (Severity: %s) ***\n" % (
            report["total_changes"], report["severity"])
        for ch in report["changes"][:50]:
            print "  [%s] %s" % (ch["change_type"], ch["path"])
            print "    Baseline : %s" % str(ch.get("baseline_value",""))[:80]
            print "    Live     : %s" % str(ch.get("live_value",""))[:80]
            print ""
        if report["total_changes"] > 50:
            print "  ... and %d more changes." % (report["total_changes"] - 50)
    else:
        print "No drift detected."


# ── Dispatch ──────────────────────────────────
if __name__ == "__main__" or True:
    cmd = "status"
    if len(sys.argv) > 1:
        cmd = sys.argv[1]

    if cmd == "status":
        print_status()
    elif cmd == "history":
        n = int(sys.argv[2]) if len(sys.argv) > 2 else 10
        print_history(n)
    elif cmd == "update-baseline":
        update_baseline()
    elif cmd == "compare":
        snap_file = sys.argv[2] if len(sys.argv) > 2 else None
        compare_specific(snap_file)
    else:
        print "Unknown command: %s" % cmd
        print __doc__
