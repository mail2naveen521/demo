# =============================================================================
# WebSphere Configuration Drift Monitor - Baseline Extractor
# Target: WAS ND 8.5.5.27, Jython 2.1 (Python 2.1 syntax only)
#
# Jython 2.1 restrictions applied:
#   - No json, hashlib, glob modules
#   - No sorted(), enumerate(), any(), all(), reversed()
#   - No ternary (x if c else y)
#   - No set() type
#   - No str.format() - uses % formatting only
#   - No with statement
#   - No except E as e  - uses except E, e
#   - No isinstance() with builtin types - uses type() comparisons
#   - No bool type
#   - No 0L literals
#   - print is a statement not a function
#   - dict.keys() returns a plain list
#   - Java interop via java.security.MessageDigest for SHA-256
#
# Run: wsadmin.sh -lang jython -f extract_baseline.py [baseline|snapshot]
# =============================================================================

import os
import sys
import time
import re

from java.security import MessageDigest
from java.lang import String as JString

# =============================================================================
# CONFIGURATION - Edit before first run
# =============================================================================
BASELINE_DIR = "/opt/drift-monitor/baseline"
SNAPSHOT_DIR = "/opt/drift-monitor/snapshots"
LOG_FILE     = "/opt/drift-monitor/logs/drift.log"
CELL_NAME    = AdminControl.getCell()

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
# SHA-256 via Java MessageDigest (no hashlib in Jython 2.1)
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
# Uses only type() comparisons - isinstance() fails with builtins in Jython 2.1
# =============================================================================

# Pre-built type constants using literals - safe in all Python/Jython versions
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

    # unicode strings and any other type - convert to string
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
        p  += 1
        buf = []
        esc = {"n": "\n", "r": "\r", "t": "\t",
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
            p += 1                # colon
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


# =============================================================================
# ADMIN CONFIG HELPERS
# =============================================================================

def _cfg_list(config_type, scope=None):
    if scope is None:
        raw = AdminConfig.list(config_type)
    else:
        raw = AdminConfig.list(config_type, scope)
    if not raw:
        return []
    result = []
    for line in raw.splitlines():
        line = line.strip()
        if line:
            result.append(line)
    return result


def _show(obj_id):
    return AdminConfig.show(obj_id).strip()


def _attr(obj_id, attr_name):
    return AdminConfig.showAttribute(obj_id, attr_name)


# =============================================================================
# CONFIG SECTION EXTRACTORS
# =============================================================================

def get_cell():
    cell_id = AdminConfig.getid("/Cell:%s/" % CELL_NAME)
    return {"id": cell_id, "attributes": _show(cell_id)}


def get_nodes():
    result = {}
    for nid in _cfg_list("Node"):
        name = _attr(nid, "name")
        result[name] = {"id": nid, "attributes": _show(nid)}
    return result


def get_servers():
    result = {}
    for sid in _cfg_list("Server"):
        name    = _attr(sid, "name")
        jvm_cfg = ""
        for jid in _cfg_list("JavaVirtualMachine", sid):
            jvm_cfg = _show(jid)
        tps = {}
        for tid in _cfg_list("ThreadPool", sid):
            tps[_attr(tid, "name")] = _show(tid)
        result[name] = {
            "id":           sid,
            "attributes":   _show(sid),
            "jvm":          jvm_cfg,
            "thread_pools": tps,
        }
    return result


def get_clusters():
    result = {}
    for cid in _cfg_list("ServerCluster"):
        name    = _attr(cid, "name")
        members = {}
        for mid in _cfg_list("ClusterMember", cid):
            members[_attr(mid, "memberName")] = _show(mid)
        result[name] = {"id": cid, "attributes": _show(cid), "members": members}
    return result


def get_datasources():
    result = {}
    for did in _cfg_list("DataSource"):
        name   = _attr(did, "name")
        cp_cfg = ""
        for cid in _cfg_list("ConnectionPool", did):
            cp_cfg = _show(cid)
        result[name] = {
            "id":              did,
            "attributes":      _show(did),
            "connection_pool": cp_cfg,
        }
    return result


def get_virtual_hosts():
    result = {}
    for vid in _cfg_list("VirtualHost"):
        name = _attr(vid, "name")
        result[name] = {"id": vid, "attributes": _show(vid)}
    return result


def get_security():
    ids = _cfg_list("Security")
    if ids:
        return _show(ids[0])
    return ""


def get_ssl():
    result = {}
    for sid in _cfg_list("SSLConfig"):
        name = _attr(sid, "alias")
        result[name] = {"id": sid, "attributes": _show(sid)}
    return result


def get_jms():
    result = {"connection_factories": {}, "queues": {}, "topics": {}}
    for cid in _cfg_list("MQQueueConnectionFactory"):
        result["connection_factories"][_attr(cid, "name")] = _show(cid)
    for qid in _cfg_list("MQQueue"):
        result["queues"][_attr(qid, "name")] = _show(qid)
    for tid in _cfg_list("MQTopic"):
        result["topics"][_attr(tid, "name")] = _show(tid)
    return result


def get_resource_env_providers():
    result = {}
    for rid in _cfg_list("ResourceEnvironmentProvider"):
        name = _attr(rid, "name")
        result[name] = {"id": rid, "attributes": _show(rid)}
    return result


def get_libraries():
    result = {}
    for lid in _cfg_list("Library"):
        name = _attr(lid, "name")
        result[name] = {"id": lid, "attributes": _show(lid)}
    return result


# =============================================================================
# SNAPSHOT BUILDER
# =============================================================================

def build_snapshot():
    log("Building configuration snapshot for cell: %s" % CELL_NAME)

    try:
        dmgr_host = AdminControl.getHost()
    except:
        dmgr_host = "unknown"

    was_version = "unknown"
    try:
        props_path = AdminControl.getConfigRepository() + \
                     "/properties/version/WAS.product"
        fh = open(props_path, "r")
        for line in fh.readlines():
            line = line.strip()
            if line[:8] == "Version=":
                was_version = line[8:]
                break
        fh.close()
    except:
        pass

    sections = {
        "cell":                   get_cell(),
        "clusters":               get_clusters(),
        "datasources":            get_datasources(),
        "jms":                    get_jms(),
        "libraries":              get_libraries(),
        "nodes":                  get_nodes(),
        "resource_env_providers": get_resource_env_providers(),
        "security":               get_security(),
        "servers":                get_servers(),
        "ssl":                    get_ssl(),
        "virtual_hosts":          get_virtual_hosts(),
    }

    hashes   = {}
    sec_keys = list(sections.keys())
    sec_keys.sort()
    for sec in sec_keys:
        hashes[sec] = sha256(_jdumps(sections[sec]))

    composite = sha256(_jdumps(hashes))

    snapshot = {
        "metadata": {
            "cell":        CELL_NAME,
            "timestamp":   time.strftime("%Y-%m-%dT%H:%M:%S"),
            "epoch":       int(time.time()),
            "dmgr_host":   dmgr_host,
            "was_version": was_version,
        },
        "sections":       sections,
        "hashes":         hashes,
        "composite_hash": composite,
    }

    log("Composite hash: %s" % composite)
    return snapshot


# =============================================================================
# PUBLIC ENTRY POINTS (called by detect_drift.py and manage_drift.py)
# =============================================================================

def save_baseline():
    ensure_dir(BASELINE_DIR)
    ensure_dir(os.path.dirname(LOG_FILE))
    snap = build_snapshot()
    path = os.path.join(BASELINE_DIR, "baseline.json")
    write_json(path, snap)
    log("Baseline saved: %s" % path)
    return path


def save_snapshot():
    ensure_dir(SNAPSHOT_DIR)
    ensure_dir(os.path.dirname(LOG_FILE))
    snap = build_snapshot()
    ts   = time.strftime("%Y%m%d_%H%M%S")
    path = os.path.join(SNAPSHOT_DIR, "snapshot_%s.json" % ts)
    write_json(path, snap)
    log("Snapshot saved: %s" % path)
    return path


# =============================================================================
# SCRIPT ENTRY POINT
# wsadmin sets sys.argv[0] to the script path when run with -f
# When imported by other scripts, sys.argv[0] will not contain this filename
# =============================================================================

def _main():
    mode = "baseline"
    if len(sys.argv) > 1:
        mode = sys.argv[1]
    if mode == "baseline":
        save_baseline()
    elif mode == "snapshot":
        save_snapshot()
    else:
        log("Unknown mode: %s  (use: baseline | snapshot)" % mode)
        sys.exit(1)


try:
    if sys.argv[0].find("extract_baseline") >= 0:
        _main()
except:
    pass
