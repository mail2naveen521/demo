# =============================================================================
# Diagnostic Script - Confirm WAS stores log file config in StreamRedirect
# Run BEFORE updating baseline to verify the config is captured correctly.
#
# wsadmin.sh -lang jython -f check_log_config.py
# =============================================================================

import sys

print "=== Checking StreamRedirect objects (log file size config) ==="
raw = AdminConfig.list("StreamRedirect")
if raw and raw.strip():
    for sr_id in raw.splitlines():
        sr_id = sr_id.strip()
        if sr_id:
            print ""
            print "StreamRedirect ID : %s" % sr_id
            print "Attributes        : %s" % AdminConfig.show(sr_id).strip()
else:
    print "WARNING: No StreamRedirect objects found."
    print "Log file config may be stored differently on this WAS version."

print ""
print "=== Checking JavaProcessDef -> StreamRedirect hierarchy ==="
server_raw = AdminConfig.list("Server")
if server_raw:
    for srv_id in server_raw.splitlines():
        srv_id = srv_id.strip()
        if not srv_id:
            continue
        srv_name = AdminConfig.showAttribute(srv_id, "name")
        jpd_raw  = AdminConfig.list("JavaProcessDef", srv_id)
        if not jpd_raw:
            continue
        for jpd_id in jpd_raw.splitlines():
            jpd_id = jpd_id.strip()
            if not jpd_id:
                continue
            print ""
            print "Server         : %s" % srv_name
            print "JavaProcessDef : %s" % jpd_id
            sr_raw2 = AdminConfig.list("StreamRedirect", jpd_id)
            if sr_raw2 and sr_raw2.strip():
                idx = 0
                for sr_id in sr_raw2.splitlines():
                    sr_id = sr_id.strip()
                    if not sr_id:
                        continue
                    if idx == 0:
                        stream = "stdout (SystemOut.log)"
                    else:
                        stream = "stderr (SystemErr.log)"
                    print "  StreamRedirect[%d] = %s" % (idx, stream)
                    print "    ID   : %s" % sr_id
                    print "    Attrs: %s" % AdminConfig.show(sr_id).strip()
                    idx += 1
            else:
                print "  WARNING: No StreamRedirect found under JavaProcessDef"

print ""
print "=== Checking RASLoggingService ==="
ras_raw = AdminConfig.list("RASLoggingService")
if ras_raw and ras_raw.strip():
    for ras_id in ras_raw.splitlines():
        ras_id = ras_id.strip()
        if ras_id:
            print "RASLoggingService Attrs: %s" % AdminConfig.show(ras_id).strip()[:300]
else:
    print "No RASLoggingService objects found."

print ""
print "=== DONE ==="
print "Key attributes to look for in StreamRedirect:"
print "  rolloverSize           - log file size limit in MB"
print "  maxNumberOfBackupFiles - number of backup log files kept"
print "  fileName               - log file path"
print "  messageFormatKind      - log format (BASIC or ADVANCED)"
