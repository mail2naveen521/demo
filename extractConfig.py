###############################################################################
# extractConfig.py  (v2.4 - DMGR config preserved)
#
# WebSphere Configuration Drift Detection - Extraction Script
# Compatible with: WAS 8.5.5.x, Jython 2.1
#
# Changes vs v2.3:
#   - DO extract DMGR node scope (Cell=X,Node=dmgrNode) - on most fixpacks
#     this works fine; per-scope error handling catches it if it doesn't.
#   - DO extract the DMGR server itself (Cell=X,Node=dmgrNode,Server=dmgr) -
#     captures DMGR JVM heap, args, logging, custom properties, etc.
#   - Still skip IHS / unmanaged nodes (they have no extractable config)
#   - Still skip NODE_AGENT servers (minimal config, lots of runtime noise)
#
# Node classification (informational - all classifications are extracted now,
# except UNMANAGED):
#   DMGR        - has DEPLOYMENT_MANAGER server -> extract node + dmgr server
#   MANAGED     - has NODE_AGENT server         -> extract node + app servers
#   UNMANAGED   - no nodeagent (e.g. IHS)        -> SKIP (not extractable)
#   EMPTY       - no servers                    -> skip
###############################################################################

import sys
import os
import time
import re

def log(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print "[%s] %s" % (ts, msg)


def ensureDir(path):
    if not os.path.exists(path):
        os.makedirs(path)


def removeTree(path):
    if not os.path.exists(path):
        return
    if os.path.isfile(path):
        os.remove(path)
        return
    for entry in os.listdir(path):
        full = os.path.join(path, entry)
        if os.path.isdir(full):
            removeTree(full)
        else:
            os.remove(full)
    os.rmdir(path)


def cleanName(raw):
    if raw is None:
        return ''
    name = raw
    parenIdx = name.find('(')
    if parenIdx >= 0:
        name = name[:parenIdx]
    return name.strip()


def isSafeName(name):
    if not name:
        return 0
    badChars = [',', '=', '[', ']', '"', "'", '\\', '\r', '\n', '\t']
    for c in badChars:
        if c in name:
            return 0
    return 1


def getCellName():
    out = AdminConfig.list('Cell')
    lines = out.splitlines()
    if not lines or not lines[0].strip():
        log("FATAL: AdminConfig.list('Cell') returned empty")
        sys.exit(10)
    return cleanName(lines[0])


def classifyNode(cellName, nodeName):
    """
    Classify a node by examining its server children.

    Returns one of:
      'DMGR'       - has DEPLOYMENT_MANAGER server (extract this!)
      'MANAGED'    - has NODE_AGENT server (regular WAS node)
      'UNMANAGED'  - has servers but no nodeagent (IHS, custom)
      'EMPTY'      - no servers found
    """
    nodeScope = '/Cell:%s/Node:%s/' % (cellName, nodeName)
    try:
        srvOut = AdminConfig.getid(nodeScope + 'Server:/')
    except Exception, e:
        log("    classify: getid failed for %s: %s" % (nodeName, str(e)))
        return 'UNMANAGED'

    serverTypes = []
    for line in srvOut.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            stype = AdminConfig.showAttribute(line, 'serverType')
            if stype:
                serverTypes.append(stype.strip())
        except:
            pass

    if not serverTypes:
        return 'EMPTY'
    if 'DEPLOYMENT_MANAGER' in serverTypes:
        return 'DMGR'
    if 'NODE_AGENT' in serverTypes:
        return 'MANAGED'
    return 'UNMANAGED'


def getNodeNamesWithType(cellName):
    """Returns list of (nodeName, nodeType) tuples."""
    nodes = []
    out = AdminConfig.list('Node')
    for line in out.splitlines():
        nm = cleanName(line)
        if not nm:
            continue
        ntype = classifyNode(cellName, nm)
        nodes.append((nm, ntype))
    return nodes


def getServerNames(cellName, nodeName):
    """Returns list of (serverName, serverType) tuples for a node."""
    servers = []
    nodeScope = '/Cell:%s/Node:%s/' % (cellName, nodeName)
    try:
        out = AdminConfig.getid(nodeScope + 'Server:/')
    except Exception, e:
        log("  WARN: getid failed for %s: %s" % (nodeScope, str(e)))
        return servers
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        sname = cleanName(line)
        try:
            stype = AdminConfig.showAttribute(line, 'serverType')
            if stype is None:
                stype = 'UNKNOWN'
            stype = stype.strip()
        except Exception, e:
            log("  WARN: showAttribute(serverType) failed for %s: %s" %
                (sname, str(e)))
            stype = 'UNKNOWN'
        servers.append((sname, stype))
    return servers


def getClusterNames():
    clusters = []
    out = AdminConfig.list('ServerCluster')
    for line in out.splitlines():
        nm = cleanName(line)
        if nm:
            clusters.append(nm)
    return clusters


def getAppNames():
    apps = []
    out = AdminApp.list()
    for line in out.splitlines():
        nm = cleanName(line)
        if nm:
            apps.append(nm)
    return apps


VOLATILE_PATTERNS = [
    re.compile(r'^#ExtractedAt=.*$'),
    re.compile(r'^#.*Extracted on .*$'),
    re.compile(r'^#.*Generated by .*$'),
    re.compile(r'^.*_Websphere_Config_Data_Id=.*$'),
    re.compile(r'^.*_Websphere_Config_Data_Version=.*$'),
    re.compile(r'^#\s*SectionTopOrderID=.*$'),
]


def normalizeFile(path):
    if not os.path.exists(path):
        return
    f = open(path, 'rb')
    try:
        raw = f.read()
    finally:
        f.close()
    text = raw.replace('\r\n', '\n').replace('\r', '\n')
    lines = text.split('\n')
    cleaned = []
    for line in lines:
        skip = 0
        for pat in VOLATILE_PATTERNS:
            if pat.match(line):
                skip = 1
                break
        if skip:
            continue
        cleaned.append(line.rstrip())
    while len(cleaned) > 0 and cleaned[-1] == '':
        cleaned.pop()
    cleaned.append('')
    out = '\n'.join(cleaned)
    f = open(path, 'wb')
    try:
        f.write(out)
    finally:
        f.close()


def extractScope(outputFile, configData, label):
    if not configData or configData.strip() == '':
        log("  SKIP %s: empty configData" % label)
        return 0

    log("Extracting %s -> %s" % (label, outputFile))
    log("  configData = %s" % repr(configData))

    try:
        AdminTask.extractConfigProperties([
            '-propertiesFileName', outputFile,
            '-configData', configData,
            '-options', '[[PortablePropertiesFile true]]'
        ])
        normalizeFile(outputFile)
        return 1
    except Exception, e:
        log("  ERROR extracting %s" % label)
        log("    Exception class: %s" % e.__class__.__name__)
        log("    Message: %s" % str(e))
        try:
            cause = e
            depth = 0
            while cause is not None and depth < 5:
                log("    [cause %d] %s: %s" %
                    (depth, cause.__class__.__name__, str(cause)))
                if hasattr(cause, 'getCause'):
                    nxt = cause.getCause()
                    if nxt is None or nxt == cause:
                        break
                    cause = nxt
                else:
                    break
                depth = depth + 1
        except:
            pass
        return 0


def extractAll(currentDir):
    ensureDir(currentDir)
    ensureDir(currentDir + '/nodes')
    ensureDir(currentDir + '/servers')
    ensureDir(currentDir + '/clusters')
    ensureDir(currentDir + '/applications')

    cellName = getCellName()
    log("Cell: %s" % repr(cellName))
    if not isSafeName(cellName):
        log("FATAL: cell name contains unsafe characters")
        sys.exit(11)

    successCount = 0
    failCount = 0
    skipCount = 0

    # 1. Cell-level config
    if extractScope(currentDir + '/cell.props',
                    'Cell=' + cellName,
                    'Cell:' + cellName):
        successCount = successCount + 1
    else:
        failCount = failCount + 1

    # 2. Discover and classify all nodes
    nodesWithType = getNodeNamesWithType(cellName)
    log("Found %d nodes:" % len(nodesWithType))
    for nm, ntype in nodesWithType:
        log("  %-20s type=%s" % (nm, ntype))

    # Build list of nodes we WILL extract:
    # - MANAGED: regular app server nodes
    # - DMGR:    deployment manager node (we want its config too!)
    # Skipped:
    # - UNMANAGED: IHS / unmanaged nodes (no extractable config)
    # - EMPTY:     no servers
    extractableNodes = []  # list of (nodeName, nodeType)
    for nm, ntype in nodesWithType:
        if ntype in ('MANAGED', 'DMGR'):
            extractableNodes.append((nm, ntype))
        else:
            log("  Skipping node %s (type=%s, not extractable)" % (nm, ntype))
            skipCount = skipCount + 1

    log("Will extract %d node(s): %s" %
        (len(extractableNodes), [n[0] for n in extractableNodes]))

    # 3. Per-node config (for both MANAGED and DMGR nodes)
    for nodeName, nodeType in extractableNodes:
        if not isSafeName(nodeName):
            log("  SKIP node with unsafe name: %s" % repr(nodeName))
            skipCount = skipCount + 1
            continue
        configData = 'Cell=%s,Node=%s' % (cellName, nodeName)
        outFile = '%s/nodes/%s.props' % (currentDir, nodeName)
        label = 'Node:%s (%s)' % (nodeName, nodeType)
        if extractScope(outFile, configData, label):
            successCount = successCount + 1
        else:
            # Per-scope failure - log but continue. DMGR node-scope extraction
            # is known to fail on some fixpacks; the DMGR server scope below
            # will still run and capture DMGR JVM config.
            failCount = failCount + 1

    # 4. Per-server config
    #
    # For MANAGED nodes: extract all APPLICATION_SERVER and ONDEMAND_ROUTER
    #                    servers; skip NODE_AGENT (minimal config, noisy).
    # For DMGR nodes:    extract the DEPLOYMENT_MANAGER server itself!
    #                    This captures DMGR JVM heap, args, logging settings,
    #                    custom properties, etc. - things we'd otherwise miss.
    for nodeName, nodeType in extractableNodes:
        if not isSafeName(nodeName):
            continue
        servers = getServerNames(cellName, nodeName)
        log("  Node %s (%s) has %d server(s)" %
            (nodeName, nodeType, len(servers)))
        for srv in servers:
            sname = srv[0]
            stype = srv[1]

            # Skip nodeagent (minimal extractable config, lots of noise)
            if stype == 'NODE_AGENT':
                log("  Skipping %s (NODE_AGENT)" % sname)
                continue

            # Extract DMGR server (this is what gives us DMGR JVM config!)
            # Extract APPLICATION_SERVER, ONDEMAND_ROUTER, WEB_SERVER, etc.
            # Anything else with a config gets extracted.
            if not isSafeName(sname):
                log("  SKIP server with unsafe name: %s" % repr(sname))
                skipCount = skipCount + 1
                continue

            configData = 'Cell=%s,Node=%s,Server=%s' % \
                         (cellName, nodeName, sname)
            outFile = '%s/servers/%s__%s.props' % \
                      (currentDir, nodeName, sname)
            label = 'Server:%s (%s on %s)' % (sname, stype, nodeName)
            if extractScope(outFile, configData, label):
                successCount = successCount + 1
            else:
                failCount = failCount + 1

    # 5. Per-cluster config
    clusters = getClusterNames()
    log("Found %d clusters: %s" % (len(clusters), clusters))
    for cluster in clusters:
        if not isSafeName(cluster):
            log("  SKIP cluster with unsafe name: %s" % repr(cluster))
            skipCount = skipCount + 1
            continue
        configData = 'Cell=%s,ServerCluster=%s' % (cellName, cluster)
        outFile = '%s/clusters/%s.props' % (currentDir, cluster)
        if extractScope(outFile, configData, 'Cluster:' + cluster):
            successCount = successCount + 1
        else:
            failCount = failCount + 1

    # 6. Per-application config
    apps = getAppNames()
    log("Found %d applications: %s" % (len(apps), apps))
    for app in apps:
        if not isSafeName(app):
            log("  SKIP app with unsafe name: %s" % repr(app))
            skipCount = skipCount + 1
            continue
        configData = 'Cell=%s,Deployment=%s' % (cellName, app)
        outFile = '%s/applications/%s.props' % (currentDir, app)
        if extractScope(outFile, configData, 'App:' + app):
            successCount = successCount + 1
        else:
            failCount = failCount + 1

    log("=====================================")
    log("Extraction complete. Success: %d, Failed: %d, Skipped: %d" %
        (successCount, failCount, skipCount))
    log("=====================================")
    return failCount


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
if len(sys.argv) < 1:
    print "Usage: wsadmin.sh -lang jython -f extractConfig.py <snapshots_root>"
    sys.exit(1)

snapshotsRoot = sys.argv[0]
currentDir = snapshotsRoot + '/current'

log("Starting WebSphere config extraction (v2.4)")
log("Snapshots root: %s" % snapshotsRoot)
log("Writing to:     %s" % currentDir)

if os.path.exists(currentDir):
    log("Removing stale %s" % currentDir)
    removeTree(currentDir)

ensureDir(snapshotsRoot)
failures = extractAll(currentDir)

log("Done. Per-scope failures: %d" % failures)
sys.exit(0)
