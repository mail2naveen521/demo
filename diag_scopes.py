###############################################################################
# diag_scopes.py
#
# Tests each scope type (cell, node, server, cluster, app) with the simplest
# possible extractConfigProperties call (no -options arg). Reports which
# scope types succeed and which fail.
#
# Run with:
#   $DMGR_PROFILE/bin/wsadmin.sh -lang jython -f diag_scopes.py
###############################################################################

import sys
import os
import time

def log(msg):
    ts = time.strftime("%H:%M:%S", time.localtime())
    print "[%s] %s" % (ts, msg)


def cleanName(raw):
    if raw is None:
        return ''
    name = raw
    parenIdx = name.find('(')
    if parenIdx >= 0:
        name = name[:parenIdx]
    return name.strip()


def dumpException(e, prefix='    '):
    print "%sException class: %s" % (prefix, e.__class__.__name__)
    print "%sMessage: %s" % (prefix, str(e))
    try:
        cause = e
        depth = 0
        while cause is not None and depth < 5:
            print "%s[cause %d] %s: %s" % (
                prefix, depth, cause.__class__.__name__, str(cause))
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


def tryExtract(label, configData, outFile):
    """
    Attempt extractConfigProperties for the given scope. Returns 1 on success.
    """
    print ""
    print "-" * 60
    print "%s" % label
    print "-" * 60
    print "  configData = %s" % repr(configData)
    print "  outFile    = %s" % repr(outFile)
    try:
        AdminTask.extractConfigProperties([
            '-propertiesFileName', outFile,
            '-configData', configData
        ])
        if os.path.exists(outFile):
            sz = os.path.getsize(outFile)
            print "  RESULT: SUCCESS (%d bytes)" % sz
            return 1
        else:
            print "  RESULT: WARN - call returned but no file written"
            return 0
    except Exception, e:
        print "  RESULT: FAILED"
        dumpException(e)
        return 0


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
outDir = '/tmp/diag_scopes'
if not os.path.exists(outDir):
    os.makedirs(outDir)

print "=" * 60
print "Scope-by-scope diagnostic for extractConfigProperties"
print "Output directory: %s" % outDir
print "=" * 60

results = {}

# ---------------------------------------------------------------------------
# Discover cell, nodes, servers, clusters, apps
# ---------------------------------------------------------------------------
log("Discovering topology...")

cellName = cleanName(AdminConfig.list('Cell').splitlines()[0])
log("Cell: %s" % repr(cellName))

nodes = []
for line in AdminConfig.list('Node').splitlines():
    nm = cleanName(line)
    if nm:
        nodes.append(nm)
log("Nodes (%d): %s" % (len(nodes), nodes))

# Get one server per node (skip nodeagent and DMGR)
servers = []
for node in nodes:
    nodeScope = '/Cell:%s/Node:%s/' % (cellName, node)
    try:
        srvOut = AdminConfig.getid(nodeScope + 'Server:/')
        for line in srvOut.splitlines():
            line = line.strip()
            if not line:
                continue
            sname = cleanName(line)
            try:
                stype = AdminConfig.showAttribute(line, 'serverType')
                if stype:
                    stype = stype.strip()
            except:
                stype = 'UNKNOWN'
            if stype not in ('NODE_AGENT', 'DEPLOYMENT_MANAGER'):
                servers.append((node, sname, stype))
    except Exception, e:
        log("WARN: getid failed for node %s: %s" % (node, str(e)))
log("Servers (%d): %s" % (len(servers), servers))

clusters = []
clusterOut = AdminConfig.list('ServerCluster')
for line in clusterOut.splitlines():
    nm = cleanName(line)
    if nm:
        clusters.append(nm)
log("Clusters (%d): %s" % (len(clusters), clusters))

apps = []
for line in AdminApp.list().splitlines():
    nm = cleanName(line)
    if nm:
        apps.append(nm)
log("Apps (%d): %s" % (len(apps), apps))

# ---------------------------------------------------------------------------
# Test each scope type (just ONE example of each, not all instances)
# ---------------------------------------------------------------------------

# Scope: Cell
results['cell'] = tryExtract(
    'TEST: Cell scope',
    'Cell=' + cellName,
    outDir + '/scope_cell.props'
)

# Scope: Node (first one)
if nodes:
    results['node'] = tryExtract(
        'TEST: Node scope (first node)',
        'Cell=%s,Node=%s' % (cellName, nodes[0]),
        outDir + '/scope_node.props'
    )
else:
    print ""
    print "TEST: Node scope - SKIPPED (no nodes found)"
    results['node'] = -1

# Scope: Server (first non-agent/DMGR server)
if servers:
    sNode, sName, sType = servers[0]
    results['server'] = tryExtract(
        'TEST: Server scope (%s on %s, type=%s)' % (sName, sNode, sType),
        'Cell=%s,Node=%s,Server=%s' % (cellName, sNode, sName),
        outDir + '/scope_server.props'
    )
else:
    print ""
    print "TEST: Server scope - SKIPPED (no app servers found)"
    results['server'] = -1

# Scope: Cluster (first one)
if clusters:
    results['cluster'] = tryExtract(
        'TEST: Cluster scope (first cluster)',
        'Cell=%s,ServerCluster=%s' % (cellName, clusters[0]),
        outDir + '/scope_cluster.props'
    )
else:
    print ""
    print "TEST: Cluster scope - SKIPPED (no clusters found)"
    results['cluster'] = -1

# Scope: Application (first one)
if apps:
    results['app'] = tryExtract(
        'TEST: Application scope (first app: %s)' % apps[0],
        'Cell=%s,Deployment=%s' % (cellName, apps[0]),
        outDir + '/scope_app.props'
    )
else:
    print ""
    print "TEST: Application scope - SKIPPED (no apps found)"
    results['app'] = -1

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print ""
print "=" * 60
print "SUMMARY"
print "=" * 60
for scope in ['cell', 'node', 'server', 'cluster', 'app']:
    rc = results.get(scope, -1)
    if rc == 1:
        status = 'SUCCESS'
    elif rc == 0:
        status = 'FAILED'
    else:
        status = 'SKIPPED'
    print "  %-10s %s" % (scope + ':', status)
print ""
print "Files written:"
for f in os.listdir(outDir):
    full = os.path.join(outDir, f)
    if os.path.isfile(full):
        print "  %s (%d bytes)" % (f, os.path.getsize(full))

print ""
print "Please share this entire output."
