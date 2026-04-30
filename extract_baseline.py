"""
WebSphere Configuration Baseline Extractor
Tested against WAS ND 8.5.5 embedded Jython 2.1.
- No hashlib  -> java.security.MessageDigest
- No json     -> hand-rolled serialiser / parser
- No sorted() -> list.sort()
- No ternary (x if c else y) -> explicit if/else blocks

Run via: wsadmin.sh -lang jython -f extract_baseline.py [baseline|snapshot]
"""

import os
import sys
import time
import re

# Java interop – always present inside WAS JVM
from java.security import MessageDigest
from java.lang     import String as JString

# ─────────────────────────────────────────────
# CONFIG  – edit before first run
# ─────────────────────────────────────────────
BASELINE_DIR = "/opt/drift-monitor/baseline"
SNAPSHOT_DIR = "/opt/drift-monitor/snapshots"
LOG_FILE     = "/opt/drift-monitor/logs/drift.log"
CELL_NAME    = AdminControl.getCell()

# ─────────────────────────────────────────────
# HELPERS – Jython 2.1 safe
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


def sorted_keys(d):
    """Return sorted list of dict keys. Replaces sorted() builtin (Python 2.4+)."""
    keys = d.keys()
    keys.sort()
    return keys


# ── SHA-256 via Java MessageDigest (replaces hashlib) ────────────────────────

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


# ── Minimal JSON serialiser (replaces json.dumps) ────────────────────────────

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

    # bool must be checked before int (bool is subclass of int in Python)
    if isinstance(obj, bool):
        if obj:
            return "true"
        else:
            return "false"

    if isinstance(obj, int) or isinstance(obj, float):
        return str(obj)

    # Jython 2.1: long is a separate type
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
            parts.append(sp2 + '"' + _escape(k) + '": ' + to_json(obj[k], ind + 2))
        return "{\n" + ",\n".join(parts) + "\n" + sp + "}"

    return '"' + _escape(str(obj)) + '"'


# ── Minimal JSON parser (replaces json.loads) ────────────────────────────────

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
        raise ValueError("Unterminated string in JSON")

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
            p += 1   # skip ':'
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
        return 1, p + 4      # use 1 instead of True for Jython 2.1 compat
    if s[p:p+5] == "false":
        return 0, p + 5      # use 0 instead of False

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


# ── File helpers ──────────────────────────────────────────────────────────────

def write_json_file(path, data):
    fh = open(path, "w")
    fh.write(to_json(data))
    fh.close()


def read_json_file(path):
    fh   = open(path, "r")
    text = fh.read()
    fh.close()
    return from_json(text)


# ─────────────────────────────────────────────
# EXTRACTION  (wsadmin AdminConfig API)
# ─────────────────────────────────────────────

def get_cell_config():
    cell_id = AdminConfig.getid("/Cell:%s/" % CELL_NAME)
    return {"id": cell_id, "attributes": AdminConfig.show(cell_id).strip()}


def get_nodes():
    nodes = {}
    raw = AdminConfig.list("Node")
    if not raw:
        return nodes
    for node_id in raw.splitlines():
        node_id = node_id.strip()
        if not node_id:
            continue
        name = AdminConfig.showAttribute(node_id, "name")
        nodes[name] = {"id": node_id,
                       "attributes": AdminConfig.show(node_id).strip()}
    return nodes


def get_servers():
    servers = {}
    raw = AdminConfig.list("Server")
    if not raw:
        return servers
    for srv_id in raw.splitlines():
        srv_id = srv_id.strip()
        if not srv_id:
            continue
        name = AdminConfig.showAttribute(srv_id, "name")

        jvm_cfg = ""
        jvm_raw = AdminConfig.list("JavaVirtualMachine", srv_id)
        if jvm_raw:
            for jvm_id in jvm_raw.splitlines():
                jvm_id = jvm_id.strip()
                if jvm_id:
                    jvm_cfg = AdminConfig.show(jvm_id).strip()

        thread_pools = {}
        tp_raw = AdminConfig.list("ThreadPool", srv_id)
        if tp_raw:
            for tp_id in tp_raw.splitlines():
                tp_id = tp_id.strip()
                if tp_id:
                    tp_name = AdminConfig.showAttribute(tp_id, "name")
                    thread_pools[tp_name] = AdminConfig.show(tp_id).strip()

        servers[name] = {
            "id":           srv_id,
            "attributes":   AdminConfig.show(srv_id).strip(),
            "jvm":          jvm_cfg,
            "thread_pools": thread_pools,
        }
    return servers


def get_datasources():
    ds_map = {}
    raw = AdminConfig.list("DataSource")
    if not raw:
        return ds_map
    for ds_id in raw.splitlines():
        ds_id = ds_id.strip()
        if not ds_id:
            continue
        name   = AdminConfig.showAttribute(ds_id, "name")
        cp_cfg = ""
        cp_raw = AdminConfig.list("ConnectionPool", ds_id)
        if cp_raw:
            for cp_id in cp_raw.splitlines():
                cp_id = cp_id.strip()
                if cp_id:
                    cp_cfg = AdminConfig.show(cp_id).strip()
        ds_map[name] = {"id":              ds_id,
                        "attributes":      AdminConfig.show(ds_id).strip(),
                        "connection_pool": cp_cfg}
    return ds_map


def get_virtual_hosts():
    vh_map = {}
    raw = AdminConfig.list("VirtualHost")
    if not raw:
        return vh_map
    for vh_id in raw.splitlines():
        vh_id = vh_id.strip()
        if not vh_id:
            continue
        name = AdminConfig.showAttribute(vh_id, "name")
        vh_map[name] = {"id": vh_id,
                        "attributes": AdminConfig.show(vh_id).strip()}
    return vh_map


def get_security_config():
    raw = AdminConfig.list("Security")
    if not raw:
        return ""
    lines = raw.splitlines()
    if lines and lines[0].strip():
        return AdminConfig.show(lines[0].strip()).strip()
    return ""


def get_clusters():
    cluster_map = {}
    raw = AdminConfig.list("ServerCluster")
    if not raw:
        return cluster_map
    for cl_id in raw.splitlines():
        cl_id = cl_id.strip()
        if not cl_id:
            continue
        name    = AdminConfig.showAttribute(cl_id, "name")
        members = {}
        mb_raw  = AdminConfig.list("ClusterMember", cl_id)
        if mb_raw:
            for mb_id in mb_raw.splitlines():
                mb_id = mb_id.strip()
                if mb_id:
                    mb_name = AdminConfig.showAttribute(mb_id, "memberName")
                    members[mb_name] = AdminConfig.show(mb_id).strip()
        cluster_map[name] = {"id":         cl_id,
                             "attributes": AdminConfig.show(cl_id).strip(),
                             "members":    members}
    return cluster_map


def get_resource_env_providers():
    rep_map = {}
    raw = AdminConfig.list("ResourceEnvironmentProvider")
    if not raw:
        return rep_map
    for rep_id in raw.splitlines():
        rep_id = rep_id.strip()
        if not rep_id:
            continue
        name = AdminConfig.showAttribute(rep_id, "name")
        rep_map[name] = {"id":         rep_id,
                         "attributes": AdminConfig.show(rep_id).strip()}
    return rep_map


def get_jms_resources():
    result = {"connection_factories": {}, "queues": {}, "topics": {}}
    for cf_id in (AdminConfig.list("MQQueueConnectionFactory") or "").splitlines():
        cf_id = cf_id.strip()
        if cf_id:
            result["connection_factories"][AdminConfig.showAttribute(cf_id, "name")] = \
                AdminConfig.show(cf_id).strip()
    for q_id in (AdminConfig.list("MQQueue") or "").splitlines():
        q_id = q_id.strip()
        if q_id:
            result["queues"][AdminConfig.showAttribute(q_id, "name")] = \
                AdminConfig.show(q_id).strip()
    for t_id in (AdminConfig.list("MQTopic") or "").splitlines():
        t_id = t_id.strip()
        if t_id:
            result["topics"][AdminConfig.showAttribute(t_id, "name")] = \
                AdminConfig.show(t_id).strip()
    return result


def get_ssl_config():
    ssl_map = {}
    raw = AdminConfig.list("SSLConfig")
    if not raw:
        return ssl_map
    for ssl_id in raw.splitlines():
        ssl_id = ssl_id.strip()
        if not ssl_id:
            continue
        name = AdminConfig.showAttribute(ssl_id, "alias")
        ssl_map[name] = {"id":         ssl_id,
                         "attributes": AdminConfig.show(ssl_id).strip()}
    return ssl_map


def get_libraries():
    lib_map = {}
    raw = AdminConfig.list("Library")
    if not raw:
        return lib_map
    for lib_id in raw.splitlines():
        lib_id = lib_id.strip()
        if not lib_id:
            continue
        name = AdminConfig.showAttribute(lib_id, "name")
        lib_map[name] = {"id":         lib_id,
                         "attributes": AdminConfig.show(lib_id).strip()}
    return lib_map


# ─────────────────────────────────────────────
# SNAPSHOT BUILDER
# ─────────────────────────────────────────────

def build_snapshot():
    log("Starting full configuration snapshot for cell: %s" % CELL_NAME)

    try:
        dmgr_host = AdminControl.getAttribute(
            AdminControl.queryNames("type=DeploymentManager,*"), "hostName")
    except:
        dmgr_host = "unknown"

    try:
        was_version = AdminControl.getAttribute(
            AdminControl.queryNames("type=Server,j2eeType=J2EEServer,name=dmgr,*"),
            "platformVersion")
    except:
        was_version = "unknown"

    sections = {
        "cell"                  : get_cell_config(),
        "nodes"                 : get_nodes(),
        "servers"               : get_servers(),
        "clusters"              : get_clusters(),
        "datasources"           : get_datasources(),
        "virtual_hosts"         : get_virtual_hosts(),
        "security"              : get_security_config(),
        "ssl"                   : get_ssl_config(),
        "jms"                   : get_jms_resources(),
        "resource_env_providers": get_resource_env_providers(),
        "libraries"             : get_libraries(),
    }

    hashes = {}
    sec_keys = sections.keys()
    sec_keys.sort()
    for section in sec_keys:
        hashes[section] = sha256_str(to_json(sections[section]))

    composite_hash = sha256_str(to_json(hashes))

    snapshot = {
        "metadata": {
            "cell"       : CELL_NAME,
            "timestamp"  : time.strftime("%Y-%m-%dT%H:%M:%S"),
            "epoch"      : int(time.time()),
            "dmgr_host"  : dmgr_host,
            "was_version": was_version,
        },
        "sections"       : sections,
        "hashes"         : hashes,
        "composite_hash" : composite_hash,
    }

    log("Snapshot composite hash: %s" % composite_hash)
    return snapshot


# ── Entry points ──────────────────────────────

def save_baseline():
    ensure_dir(BASELINE_DIR)
    ensure_dir(os.path.dirname(LOG_FILE))
    snap          = build_snapshot()
    baseline_path = os.path.join(BASELINE_DIR, "baseline.json")
    write_json_file(baseline_path, snap)
    log("Baseline saved to: %s" % baseline_path)
    return baseline_path


def save_snapshot():
    ensure_dir(SNAPSHOT_DIR)
    ensure_dir(os.path.dirname(LOG_FILE))
    snap      = build_snapshot()
    ts        = time.strftime("%Y%m%d_%H%M%S")
    snap_path = os.path.join(SNAPSHOT_DIR, "snapshot_%s.json" % ts)
    write_json_file(snap_path, snap)
    log("Snapshot saved to: %s" % snap_path)
    return snap_path


# ── Script entry ──────────────────────────────

if __name__ == "__main__" or 1:
    mode = "baseline"
    if len(sys.argv) > 1:
        mode = sys.argv[1]
    if mode == "baseline":
        save_baseline()
    elif mode == "snapshot":
        save_snapshot()
    else:
        log("Unknown mode: %s  (use 'baseline' or 'snapshot')" % mode)
        sys.exit(1)
