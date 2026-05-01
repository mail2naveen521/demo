###############################################################################
# diag_odr.py
#
# Targeted diagnostic for ODR node extraction failure.
# Tests several alternative extract approaches to isolate the cause.
#
# Run with:
#   $DMGR_PROFILE/bin/wsadmin.sh -lang jython -f diag_odr.py
###############################################################################

import sys
import os
import time

NODE = 'OdrNode1'   # the failing node

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


def dumpException(e, prefix='      '):
    print "%sclass: %s" % (prefix, e.__class__.__name__)
    print "%smsg: %s" % (prefix, str(e))
    try:
        cause = e
        depth = 0
        while cause is not None and depth < 5:
            print "%s[cause %d] %s: %s" % (prefix, depth,
                                            cause.__class__.__name__,
                                            str(cause))
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


def tryIt(label, args, outFile):
    print ""
    print "-" * 60
    print label
    print "-" * 60
    print "  args = %s" % args
    if os.path.exists(outFile):
        os.remove(outFile)
    try:
        AdminTask.extractConfigProperties(args)
        if os.path.exists(outFile):
            sz = os.path.getsize(outFile)
            print "  RESULT: SUCCESS (%d bytes)" % sz
            return 1
        else:
            print "  RESULT: returned but no file"
            return 0
    except Exception, e:
        print "  RESULT: FAILED"
        dumpException(e)
        return 0


outDir = '/tmp/diag_odr'
if not os.path.exists(outDir):
    os.makedirs(outDir)

cellName = cleanName(AdminConfig.list('Cell').splitlines()[0])
log("Cell: %s" % repr(cellName))
log("Diagnosing failure on node: %s" % NODE)
print ""

# ---------------------------------------------------------------------------
# Check 1: is the nodeagent running?
# ---------------------------------------------------------------------------
print "=" * 60
print "CHECK 1: is the nodeagent for %s running?" % NODE
print "=" * 60
try:
    naMBean = AdminControl.completeObjectName(
        'type=NodeAgent,node=%s,*' % NODE)
    if naMBean and naMBean.strip():
        print "  Nodeagent MBean found: %s" % naMBean
        print "  -> Nodeagent IS running and reachable"
    else:
        print "  Nodeagent MBean NOT found"
        print "  -> Nodeagent for %s is STOPPED or unreachable" % NODE
        print "     (this alone could cause the extract to fail)"
except Exception, e:
    print "  Could not check: %s" % str(e)

# ---------------------------------------------------------------------------
# Check 2: list servers on this node
# ---------------------------------------------------------------------------
print ""
print "=" * 60
print "CHECK 2: what servers are on %s?" % NODE
print "=" * 60
nodeScope = '/Cell:%s/Node:%s/' % (cellName, NODE)
try:
    srvOut = AdminConfig.getid(nodeScope + 'Server:/')
    print "  Raw output:"
    print "  %s" % repr(srvOut)
    print ""
    print "  Parsed servers:"
    for line in srvOut.splitlines():
        line = line.strip()
        if not line:
            continue
        sname = cleanName(line)
        try:
            stype = AdminConfig.showAttribute(line, 'serverType')
        except:
            stype = 'UNKNOWN'
        print "    name=%s  type=%s" % (sname, stype)
except Exception, e:
    print "  Failed: %s" % str(e)

# ---------------------------------------------------------------------------
# Test A: Node scope WITHOUT -options (simplest possible)
# ---------------------------------------------------------------------------
tryIt(
    "TEST A: Node scope, NO -options",
    ['-propertiesFileName', outDir + '/test_a.props',
     '-configData', 'Cell=%s,Node=%s' % (cellName, NODE)],
    outDir + '/test_a.props'
)

# ---------------------------------------------------------------------------
# Test B: Node scope WITH options (what main script uses)
# ---------------------------------------------------------------------------
tryIt(
    "TEST B: Node scope WITH [[PortablePropertiesFile true]]",
    ['-propertiesFileName', outDir + '/test_b.props',
     '-configData', 'Cell=%s,Node=%s' % (cellName, NODE),
     '-options', '[[PortablePropertiesFile true]]'],
    outDir + '/test_b.props'
)

# ---------------------------------------------------------------------------
# Test C: Server scope (the ODR server directly)
# ---------------------------------------------------------------------------
# Find first server on this node
firstServer = None
firstServerType = None
try:
    srvOut = AdminConfig.getid(nodeScope + 'Server:/')
    for line in srvOut.splitlines():
        line = line.strip()
        if not line:
            continue
        sname = cleanName(line)
        try:
            stype = AdminConfig.showAttribute(line, 'serverType')
            stype = stype.strip() if stype else 'UNKNOWN'
        except:
            stype = 'UNKNOWN'
        if stype not in ('NODE_AGENT', 'DEPLOYMENT_MANAGER'):
            firstServer = sname
            firstServerType = stype
            break
except:
    pass

if firstServer:
    tryIt(
        "TEST C: Server scope (%s, type=%s) - skipping node level" %
            (firstServer, firstServerType),
        ['-propertiesFileName', outDir + '/test_c.props',
         '-configData', 'Cell=%s,Node=%s,Server=%s' %
                        (cellName, NODE, firstServer)],
        outDir + '/test_c.props'
    )
else:
    print ""
    print "TEST C: SKIPPED - no non-agent server found on %s" % NODE

# ---------------------------------------------------------------------------
# Test D: Node scope with selectedSubTypes filter (exclude ODR types)
# Some XD/WVE config types break PFBC. Try extracting only common types.
# ---------------------------------------------------------------------------
commonTypes = '[Variable JavaProcessDef Property NameSpaceBinding ResourceEnvironmentProvider]'
tryIt(
    "TEST D: Node scope, selectedSubTypes filter (common types only)",
    ['-propertiesFileName', outDir + '/test_d.props',
     '-configData', 'Cell=%s,Node=%s' % (cellName, NODE),
     '-filterMechanism', 'SELECTED_SUBTYPES',
     '-selectedSubTypes', commonTypes],
    outDir + '/test_d.props'
)

# ---------------------------------------------------------------------------
# Test E: Same as D but with PortablePropertiesFile option
# ---------------------------------------------------------------------------
tryIt(
    "TEST E: Node scope, filtered, with options",
    ['-propertiesFileName', outDir + '/test_e.props',
     '-configData', 'Cell=%s,Node=%s' % (cellName, NODE),
     '-filterMechanism', 'SELECTED_SUBTYPES',
     '-selectedSubTypes', commonTypes,
     '-options', '[[PortablePropertiesFile true]]'],
    outDir + '/test_e.props'
)

# ---------------------------------------------------------------------------
# Test F: Node scope with EXCLUDED_SUBTYPES (everything EXCEPT ODR types)
# ---------------------------------------------------------------------------
excludeTypes = '[WorkClass RoutingRule TransactionClass ServiceClass ServicePolicy ARFMSubsystem]'
tryIt(
    "TEST F: Node scope, EXCLUDED_SUBTYPES (skip ODR-specific types)",
    ['-propertiesFileName', outDir + '/test_f.props',
     '-configData', 'Cell=%s,Node=%s' % (cellName, NODE),
     '-filterMechanism', 'NO_SUBTYPES',
     '-selectedSubTypes', excludeTypes,
     '-options', '[[PortablePropertiesFile true]]'],
    outDir + '/test_f.props'
)

print ""
print "=" * 60
print "Files produced:"
print "=" * 60
for f in sorted(os.listdir(outDir)):
    full = os.path.join(outDir, f)
    if os.path.isfile(full):
        sz = os.path.getsize(full)
        print "  %s (%d bytes)" % (f, sz)

print ""
print "Please share this entire output."
