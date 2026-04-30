# =============================================================================
# WebSphere Configuration Drift Monitor - Operator Utility
# Compatible: WAS ND 8.5.5.27, Jython 2.7
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
    return sorted(f for f in os.listdir(directory) if f.startswith(prefix))


def hr(ch="=", w=70):
    print(ch * w)


def cmd_status():
    files = list_files(REPORT_DIR, "drift_report_")
    if not files:
        print("No drift reports found. Has the monitor run yet?")
        return
    rpt = extractor.read_json(os.path.join(REPORT_DIR, files[-1]))
    hr()
    print("  WebSphere Drift Monitor - Status")
    hr()
    print("Cell            : {0}".format(rpt.get("cell", "unknown")))
    print("Last Check      : {0}".format(rpt.get("run_at", "unknown")))
    print("Baseline From   : {0}".format(rpt.get("baseline_timestamp", "unknown")))
    if rpt.get("drift_detected"):
        print("Status          : *** DRIFT DETECTED ***")
        print("Severity        : {0}".format(rpt.get("severity", "?")))
        print("Total Changes   : {0}".format(rpt.get("total_changes", 0)))
        print("Critical Changes: {0}".format(rpt.get("critical_change_count", 0)))
        print("")
        hr("-")
        print("SECTION SUMMARY")
        hr("-")
        summary = rpt.get("section_summary", {})
        for sec in sorted(summary):
            info = summary[sec]
            icon = "X" if info["status"] == "DRIFTED" else "OK"
            print("  [{0}]  {1:<30}  {2}  ({3} changes)".format(
                icon, sec, info["status"], info["change_count"]))
        print("")
        print("Report: {0}".format(os.path.join(REPORT_DIR, files[-1])))
    else:
        print("Status          : CLEAN - No drift detected")
    hr()


def cmd_history(n=10):
    files = list_files(REPORT_DIR, "drift_report_")[-n:]
    hr()
    print("  Drift Check History (last {0})".format(n))
    hr()
    print("  {0:<22}  {1:<10}  {2:<8}  {3}".format(
        "RUN_AT", "STATUS", "CHANGES", "SEVERITY"))
    hr("-")
    for fname in reversed(files):
        try:
            r        = extractor.read_json(os.path.join(REPORT_DIR, fname))
            status   = "DRIFTED" if r.get("drift_detected") else "CLEAN"
            severity = r.get("severity", "-") if r.get("drift_detected") else "-"
            print("  {0:<22}  {1:<10}  {2:<8}  {3}".format(
                r.get("run_at", "?"), status, r.get("total_changes", 0), severity))
        except Exception as e:
            print("  [error reading {0}: {1}]".format(fname, e))
    hr()


def cmd_update_baseline():
    hr()
    print("  Refreshing Baseline")
    hr()
    print("Capturing configuration from DMGR...")
    snap     = extractor.build_snapshot()
    old_path = os.path.join(BASELINE_DIR, "baseline.json")
    if os.path.exists(old_path):
        arch_dir = os.path.join(BASELINE_DIR, "archive")
        if not os.path.exists(arch_dir):
            os.makedirs(arch_dir)
        ts        = time.strftime("%Y%m%d_%H%M%S")
        arch_path = os.path.join(arch_dir, "baseline_{0}.json".format(ts))
        with open(old_path, "r") as src, open(arch_path, "w") as dst:
            dst.write(src.read())
        print("Previous baseline archived: {0}".format(arch_path))
    extractor.write_json(old_path, snap)
    print("New baseline     : {0}".format(old_path))
    print("Composite hash   : {0}".format(snap["composite_hash"]))
    print("Timestamp        : {0}".format(snap["metadata"]["timestamp"]))
    hr()


def cmd_compare(snapshot_file=None):
    ref_path  = snapshot_file or os.path.join(BASELINE_DIR, "baseline.json")
    print("Reference : {0}".format(ref_path))
    reference = extractor.read_json(ref_path)
    print("Capturing live configuration...")
    live_snap = extractor.build_snapshot()
    report    = detector.build_drift_report(reference, live_snap)
    if report["drift_detected"]:
        print("\n*** {0} changes found (severity={1}) ***\n".format(
            report["total_changes"], report["severity"]))
        for idx, ch in enumerate(report["changes"][:50], 1):
            print("  [{0}] {1}".format(ch["change_type"], ch["path"]))
            print("    Baseline : {0}".format(str(ch.get("baseline_value", ""))[:80]))
            print("    Live     : {0}".format(str(ch.get("live_value", ""))[:80]))
        if report["total_changes"] > 50:
            print("  ... and {0} more changes.".format(report["total_changes"] - 50))
    else:
        print("No drift detected.")


# =============================================================================
# ENTRY
# =============================================================================

def _main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "status":
        cmd_status()
    elif cmd == "history":
        n = int(sys.argv[2]) if len(sys.argv) > 2 else 10
        cmd_history(n)
    elif cmd == "update-baseline":
        cmd_update_baseline()
    elif cmd == "compare":
        cmd_compare(sys.argv[2] if len(sys.argv) > 2 else None)
    else:
        print("Unknown command: {0}".format(cmd))
        print("Commands: status | history [N] | update-baseline | compare [file]")


try:
    if "manage_drift" in sys.argv[0]:
        _main()
except (IndexError, TypeError):
    pass
