# =============================================================================
# WebSphere Configuration Drift Monitor - Baseline Extractor
# Compatible: WAS ND 8.5.5.27, Jython 2.7
# Run: wsadmin.sh -lang jython -f extract_baseline.py [baseline|snapshot]
# =============================================================================

import os
import sys
import time
import re
import json
import hashlib

# Java interop - available in all WAS Jython runtimes
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
    """SHA-256 via Java MessageDigest - always available in WAS JVM."""
    md  = MessageDigest.getInstance("SHA-256")
    raw = md.digest(JString(s).getBytes("UTF-8"))
    return "".join("{0:02x}".format(b & 0xFF) for b in raw)


def write_json(path, data):
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)


def read_json(path):
    with open(path, "r") as fh:
        return json.load(fh)


# =============================================================================
# CONFIG EXTRACTION  (wsadmin AdminConfig API)
# =============================================================================

def _list(config_type, scope=None):
    """Return list of non-empty config object IDs."""
    raw = AdminConfig.list(config_type) if scope is None \
          else AdminConfig.list(config_type, scope)
    if not raw:
        return []
    return [line.strip() for line in raw.splitlines() if line.strip()]


def _show(obj_id):
    return AdminConfig.show(obj_id).strip()


def _attr(obj_id, attr_name):
    return AdminConfig.showAttribute(obj_id, attr_name)


def get_cell():
    cell_id = AdminConfig.getid("/Cell:{0}/".format(CELL_NAME))
    return {"id": cell_id, "attributes": _show(cell_id)}


def get_nodes():
    result = {}
    for nid in _list("Node"):
        name = _attr(nid, "name")
        result[name] = {"id": nid, "attributes": _show(nid)}
    return result


def get_servers():
    result = {}
    for sid in _list("Server"):
        name    = _attr(sid, "name")
        jvm_cfg = ""
        for jid in _list("JavaVirtualMachine", sid):
            jvm_cfg = _show(jid)
        thread_pools = {}
        for tid in _list("ThreadPool", sid):
            thread_pools[_attr(tid, "name")] = _show(tid)
        result[name] = {
            "id":           sid,
            "attributes":   _show(sid),
            "jvm":          jvm_cfg,
            "thread_pools": thread_pools,
        }
    return result


def get_clusters():
    result = {}
    for cid in _list("ServerCluster"):
        name    = _attr(cid, "name")
        members = {}
        for mid in _list("ClusterMember", cid):
            members[_attr(mid, "memberName")] = _show(mid)
        result[name] = {"id": cid, "attributes": _show(cid), "members": members}
    return result


def get_datasources():
    result = {}
    for did in _list("DataSource"):
        name   = _attr(did, "name")
        cp_cfg = ""
        for cid in _list("ConnectionPool", did):
            cp_cfg = _show(cid)
        result[name] = {
            "id":             did,
            "attributes":     _show(did),
            "connection_pool": cp_cfg,
        }
    return result


def get_virtual_hosts():
    result = {}
    for vid in _list("VirtualHost"):
        name = _attr(vid, "name")
        result[name] = {"id": vid, "attributes": _show(vid)}
    return result


def get_security():
    ids = _list("Security")
    return _show(ids[0]) if ids else ""


def get_ssl():
    result = {}
    for sid in _list("SSLConfig"):
        name = _attr(sid, "alias")
        result[name] = {"id": sid, "attributes": _show(sid)}
    return result


def get_jms():
    result = {"connection_factories": {}, "queues": {}, "topics": {}}
    for cid in _list("MQQueueConnectionFactory"):
        result["connection_factories"][_attr(cid, "name")] = _show(cid)
    for qid in _list("MQQueue"):
        result["queues"][_attr(qid, "name")] = _show(qid)
    for tid in _list("MQTopic"):
        result["topics"][_attr(tid, "name")] = _show(tid)
    return result


def get_resource_env_providers():
    result = {}
    for rid in _list("ResourceEnvironmentProvider"):
        name = _attr(rid, "name")
        result[name] = {"id": rid, "attributes": _show(rid)}
    return result


def get_libraries():
    result = {}
    for lid in _list("Library"):
        name = _attr(lid, "name")
        result[name] = {"id": lid, "attributes": _show(lid)}
    return result


# =============================================================================
# SNAPSHOT BUILDER
# =============================================================================

def build_snapshot():
    log("Building configuration snapshot for cell: {0}".format(CELL_NAME))

    try:
        dmgr_host = AdminControl.getHost()
    except Exception:
        dmgr_host = "unknown"

    was_version = "unknown"
    try:
        props_path = os.path.join(
            AdminControl.getConfigRepository(),
            "properties", "version", "WAS.product"
        )
        with open(props_path, "r") as fh:
            for line in fh:
                if line.strip().startswith("Version="):
                    was_version = line.strip()[8:]
                    break
    except Exception:
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

    hashes = {sec: sha256(json.dumps(sections[sec], sort_keys=True))
              for sec in sorted(sections.keys())}

    composite = sha256(json.dumps(hashes, sort_keys=True))

    snapshot = {
        "metadata": {
            "cell":        CELL_NAME,
            "timestamp":   time.strftime("%Y-%m-%dT%H:%M:%S"),
            "epoch":       int(time.time()),
            "dmgr_host":   dmgr_host,
            "was_version": was_version,
        },
        "sections":        sections,
        "hashes":          hashes,
        "composite_hash":  composite,
    }

    log("Composite hash: {0}".format(composite))
    return snapshot


# =============================================================================
# PUBLIC ENTRY POINTS
# =============================================================================

def save_baseline():
    ensure_dir(BASELINE_DIR)
    ensure_dir(os.path.dirname(LOG_FILE))
    snap = build_snapshot()
    path = os.path.join(BASELINE_DIR, "baseline.json")
    write_json(path, snap)
    log("Baseline saved: {0}".format(path))
    return path


def save_snapshot():
    ensure_dir(SNAPSHOT_DIR)
    ensure_dir(os.path.dirname(LOG_FILE))
    snap = build_snapshot()
    ts   = time.strftime("%Y%m%d_%H%M%S")
    path = os.path.join(SNAPSHOT_DIR, "snapshot_{0}.json".format(ts))
    write_json(path, snap)
    log("Snapshot saved: {0}".format(path))
    return path


# =============================================================================
# SCRIPT ENTRY  (wsadmin sets sys.argv[0] to the script path)
# =============================================================================

def _main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "baseline"
    if mode == "baseline":
        save_baseline()
    elif mode == "snapshot":
        save_snapshot()
    else:
        log("Unknown mode: {0}  (use: baseline | snapshot)".format(mode))
        sys.exit(1)


try:
    if "extract_baseline" in sys.argv[0]:
        _main()
except (IndexError, TypeError):
    pass
