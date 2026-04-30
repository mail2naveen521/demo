# =============================================================================
# WebSphere Configuration Drift Monitor - Operator Utility
# Target: WAS ND 8.5.5.27, Jython 2.1 (Python 2.1 syntax only)
# Run: wsadmin.sh -lang jython -f manage_drift.py [command]
#
# Commands:
#   status            Show latest drift result
#   history [N]       Show last N results (default 10)
#   update-baseline   Capture fresh baseline after approved changes
#   compare [file]    Compare live config vs a specific snapshot
# =============================================================================

import os
import sys
import time

MONITOR_HOME = "/opt/drift-monitor"
BASELINE_DIR = os.path.join(MONITOR_HOME, "baseline")
REPORT_DIR   = os.path.join(MONITOR_HOME, "reports")
SCRIPTS_DIR  = os.path.join(MONITOR_HOME, "scripts")

if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

import extract_baseline as extractor
import detect_drift     as detector


def list_files(directory, prefix):
    if not os.path.exists(directory):
        return []
    result = []
    for fname in os.listdir(directory):
        if fname[:len(prefix)] == prefix:
            result.append(fname)
    result.sort()
    return result


def hr(ch="=", w=70):
    print ch * w


def cmd_status():
    files = list_files(REPORT_DIR, "drift_report_")
    if not files:
        print "No drift reports found. Has the monitor run yet?"
        return
    rpt = extractor.read_json(os.path.join(REPORT_DIR, files[-1]))
    hr()
    print "  WebSphere Drift Monitor - Status"
    hr()
    print "Cell            : %s" % rpt.get("cell", "unknown")
    print "Last Check      : %s" % rpt.get("run_at", "unknown")
    print "Baseline From   : %s" % rpt.get("baseline_timestamp", "unknown")
    if rpt.get("drift_detected"):
        print "Status          : *** DRIFT DETECTED ***"
        print "Severity        : %s" % rpt.get("severity", "?")
        print "Total Changes   : %d" % rpt.get("total_changes", 0)
        print "Critical Changes: %d" % rpt.get("critical_change_count", 0)
        print ""
        hr("-")
        print "SECTION SUMMARY"
        hr("-")
        summary  = rpt.get("section_summary", {})
        sec_keys = list(summary.keys())
        sec_keys.sort()
        for sec in sec_keys:
            info = summary[sec]
            if info["status"] == "DRIFTED":
                icon = "X"
            else:
                icon = "OK"
            print "  [%s]  %-30s  %s  (%d changes)" % (icon, sec, info["status"], info["change_count"])
        print ""
        print "Report: %s" % os.path.join(REPORT_DIR, files[-1])
    else:
        print "Status          : CLEAN - No drift detected"
    hr()


def cmd_history(n=10):
    files = list_files(REPORT_DIR, "drift_report_")
    files = files[-n:]
    hr()
    print "  Drift Check History (last %d)" % n
    hr()
    print "  %-22s  %-10s  %-8s  %s" % ("RUN_AT", "STATUS", "CHANGES", "SEVERITY")
    hr("-")
    i = len(files) - 1
    while i >= 0:
        fname = files[i]
        try:
            r = extractor.read_json(os.path.join(REPORT_DIR, fname))
            if r.get("drift_detected"):
                status   = "DRIFTED"
                severity = r.get("severity", "-")
            else:
                status   = "CLEAN"
                severity = "-"
            print "  %-22s  %-10s  %-8d  %s" % (r.get("run_at", "?"), status, r.get("total_changes", 0), severity)
        except Exception, e:
            print "  [error reading %s: %s]" % (fname, str(e))
        i -= 1
    hr()


def cmd_update_baseline():
    hr()
    print "  Refreshing Baseline"
    hr()
    print "Capturing configuration from DMGR..."
    snap     = extractor.build_snapshot()
    old_path = os.path.join(BASELINE_DIR, "baseline.json")
    if os.path.exists(old_path):
        arch_dir = os.path.join(BASELINE_DIR, "archive")
        if not os.path.exists(arch_dir):
            os.makedirs(arch_dir)
        ts        = time.strftime("%Y%m%d_%H%M%S")
        arch_path = os.path.join(arch_dir, "baseline_%s.json" % ts)
        fh_r = open(old_path, "r")
        data = fh_r.read()
        fh_r.close()
        fh_w = open(arch_path, "w")
        fh_w.write(data)
        fh_w.close()
        print "Previous baseline archived: %s" % arch_path
    extractor.write_json(old_path, snap)
    print "New baseline     : %s" % old_path
    print "Composite hash   : %s" % snap["composite_hash"]
    print "Timestamp        : %s" % snap["metadata"]["timestamp"]
    hr()


def cmd_compare(snapshot_file=None):
    if snapshot_file:
        ref_path = snapshot_file
    else:
        ref_path = os.path.join(BASELINE_DIR, "baseline.json")
    print "Reference : %s" % ref_path
    reference = extractor.read_json(ref_path)
    print "Capturing live configuration..."
    live_snap = extractor.build_snapshot()
    report    = detector.build_drift_report(reference, live_snap)
    if report["drift_detected"]:
        print "\n*** %d changes found (severity=%s) ***\n" % (report["total_changes"], report["severity"])
        shown = 0
        for ch in report["changes"]:
            if shown >= 50:
                break
            print "  [%s] %s" % (ch["change_type"], ch["path"])
            print "    Baseline : %s" % str(ch.get("baseline_value", ""))[:80]
            print "    Live     : %s" % str(ch.get("live_value", ""))[:80]
            print ""
            shown += 1
        if report["total_changes"] > 50:
            print "  ... and %d more changes." % (report["total_changes"] - 50)
    else:
        print "No drift detected."


# =============================================================================
# SCRIPT ENTRY POINT
# =============================================================================

def _main():
    # wsadmin sets sys.argv to the args passed after -f script.py
    # e.g. wsadmin -f manage_drift.py update-baseline -> sys.argv = ["update-baseline"]
    cmd = "status"
    if len(sys.argv) > 0:
        cmd = sys.argv[0]
    if cmd == "status":
        cmd_status()
    elif cmd == "history":
        if len(sys.argv) > 1:
            cmd_history(int(sys.argv[1]))
        else:
            cmd_history(10)
    elif cmd == "update-baseline":
        cmd_update_baseline()
    elif cmd == "compare":
        if len(sys.argv) > 1:
            cmd_compare(sys.argv[1])
        else:
            cmd_compare()
    else:
        print "Unknown command: %s" % cmd
        print "Commands: status | history [N] | update-baseline | compare [file]"


# manage_drift.py is always run directly, never imported.
# wsadmin sets sys.argv to the arguments passed after the script name.
_main()
