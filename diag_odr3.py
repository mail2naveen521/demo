###############################################################################
# diag_odr3.py
#
# Hardened version that catches BOTH Python (Exception) and Java
# (java.lang.Throwable) exceptions, so WAS exceptions don't kill the
# whole script and we can see all 6 test results.
#
# Run with:
#   $DMGR_PROFILE/bin/wsadmin.sh -lang jython -f diag_odr3.py
###############################################################################

import sys
import os

# Import Java exception classes so we can catch them explicitly
import java.lang.Throwable
import java.lang.Exception as JLException

NODE = 'OdrNode1'
OUTDIR = '/tmp/diag_odr3'

# Get cell name
cellRaw = AdminConfig.list('Cell').splitlines()[0]
parenIdx = cellRaw.find('(')
if parenIdx >= 0:
    cellName = cellRaw[:parenIdx].strip()
else:
    cellName = cellRaw.strip()

print "Cell: %s" % repr(cellName)
print "Diagnosing: %s" % NODE
print ""

if not os.path.exists(OUTDIR):
    os.makedirs(OUTDIR)


def runTest(num, label, args, outFile):
    print ""
    print "------------------------------------------------------------"
    print "TEST %s: %s" % (num, label)
    print "------------------------------------------------------------"
    print "  args:"
    for a in args:
        print "    %s" % repr(a)
    if os.path.exists(outFile):
        os.remove(outFile)
    # Catch ANY throwable - Python or Java - so script doesn't die
    success = 0
    errClass = None
    errMsg = None
    try:
        AdminTask.extractConfigProperties(args)
        success = 1
    except java.lang.Throwable, jt:
        errClass = jt.__class__.__name__
        try:
            errMsg = jt.getMessage()
        except:
            errMsg = str(jt)
    except Exception, e:
        errClass = e.__class__.__name__
        errMsg = str(e)
    except:
        # Bare except - last resort. In Jython 2.1, sys.exc_info() returns
        # (type, value, traceback)
        ei = sys.exc_info()
        errClass = str(ei[0])
        errMsg = str(ei[1])

    if success:
        if os.path.exists(outFile):
            sz = os.path.getsize(outFile)
            print "  RESULT: SUCCESS (%d bytes)" % sz
        else:
            print "  RESULT: returned but no file"
    else:
        print "  RESULT: FAILED"
        print "    class: %s" % errClass
        print "    msg: %s" % errMsg
    return success


def safeCheck(label, fn):
    """Run a check function, swallowing any exception."""
    print ""
    print "============================================================"
    print label
    print "============================================================"
    try:
        fn()
    except java.lang.Throwable, jt:
        print "  CHECK FAILED with Java exception: %s" % str(jt)
    except Exception, e:
        print "  CHECK FAILED: %s" % str(e)
    except:
        ei = sys.exc_info()
        print "  CHECK FAILED: %s" % str(ei[1])


# CHECK 1: nodeagent
def check1():
    naMBean = AdminControl.completeObjectName(
        'type=NodeAgent,node=%s,*' % NODE)
    if naMBean:
        naMBean = naMBean.strip()
    if naMBean:
        print "  YES - nodeagent reachable: %s" % naMBean
    else:
        print "  NO - nodeagent NOT reachable (stopped or unreachable)"

safeCheck("CHECK 1: nodeagent reachable?", check1)


# CHECK 2: servers on this node
firstServer = ['']    # use list as mutable holder for closure
firstServerType = ['']

def check2():
    nodeScope = '/Cell:%s/Node:%s/' % (cellName, NODE)
    srvOut = AdminConfig.getid(nodeScope + 'Server:/')
    print "  Raw: %s" % repr(srvOut)
    for line in srvOut.splitlines():
        line = line.strip()
        if not line:
            continue
        sn = line
        p = sn.find('(')
        if p >= 0:
            sn = sn[:p].strip()
        try:
            stype = AdminConfig.showAttribute(line, 'serverType')
            if stype:
                stype = stype.strip()
            else:
                stype = 'UNKNOWN'
        except:
            stype = 'UNKNOWN'
        print "    %s (type=%s)" % (sn, stype)
        if stype != 'NODE_AGENT':
            if not firstServer[0]:
                firstServer[0] = sn
                firstServerType[0] = stype

safeCheck("CHECK 2: servers on %s" % NODE, check2)


# CHECK 3: does the node config directory exist on disk?
def check3():
    # Try common WAS install paths
    candidates = []
    if 'WAS_HOME' in os.environ:
        candidates.append(os.environ['WAS_HOME'])
    candidates.append('/opt/IBM/WebSphere/AppServer')
    # Look for any DMgr profile
    for base in candidates:
        prof = base + '/profiles'
        if os.path.exists(prof):
            for p in os.listdir(prof):
                cellDir = '%s/%s/config/cells/%s' % (prof, p, cellName)
                if os.path.exists(cellDir):
                    nodesDir = cellDir + '/nodes'
                    if os.path.exists(nodesDir):
                        print "  Cell config dir: %s" % cellDir
                        print "  Node directories on disk:"
                        for nd in os.listdir(nodesDir):
                            full = nodesDir + '/' + nd
                            if os.path.isdir(full):
                                marker = ''
                                if nd == NODE:
                                    marker = '  <-- target node'
                                print "    %s%s" % (nd, marker)
                        return
    print "  Could not find cell config directory automatically."
    print "  Manually check: ls $DMGR_PROFILE/config/cells/%s/nodes/" % cellName

safeCheck("CHECK 3: node config dir on disk", check3)


# Build test args
nodeScope_cd = 'Cell=%s,Node=%s' % (cellName, NODE)

# TEST A: simplest possible
runTest('A', 'Node scope, NO -options',
    ['-propertiesFileName', OUTDIR + '/A.props',
     '-configData', nodeScope_cd],
    OUTDIR + '/A.props')

# TEST B: with options
runTest('B', 'Node scope WITH PortablePropertiesFile',
    ['-propertiesFileName', OUTDIR + '/B.props',
     '-configData', nodeScope_cd,
     '-options', '[[PortablePropertiesFile true]]'],
    OUTDIR + '/B.props')

# TEST C: server scope (skip node level)
if firstServer[0]:
    serverScope_cd = 'Cell=%s,Node=%s,Server=%s' % \
        (cellName, NODE, firstServer[0])
    runTest('C', 'Server scope (%s, %s)' %
                 (firstServer[0], firstServerType[0]),
        ['-propertiesFileName', OUTDIR + '/C.props',
         '-configData', serverScope_cd],
        OUTDIR + '/C.props')
else:
    print ""
    print "TEST C: SKIPPED - no non-agent server found"

# TEST D: filter
runTest('D', 'Node scope, SELECTED_SUBTYPES (common types)',
    ['-propertiesFileName', OUTDIR + '/D.props',
     '-configData', nodeScope_cd,
     '-filterMechanism', 'SELECTED_SUBTYPES',
     '-selectedSubTypes',
     '[Variable JavaProcessDef Property NameSpaceBinding]'],
    OUTDIR + '/D.props')

# TEST E: D + options
runTest('E', 'Node scope, SELECTED_SUBTYPES + portable',
    ['-propertiesFileName', OUTDIR + '/E.props',
     '-configData', nodeScope_cd,
     '-filterMechanism', 'SELECTED_SUBTYPES',
     '-selectedSubTypes',
     '[Variable JavaProcessDef Property NameSpaceBinding]',
     '-options', '[[PortablePropertiesFile true]]'],
    OUTDIR + '/E.props')

# TEST F: exclude ODR types
runTest('F', 'Node scope, NO_SUBTYPES (exclude ODR types)',
    ['-propertiesFileName', OUTDIR + '/F.props',
     '-configData', nodeScope_cd,
     '-filterMechanism', 'NO_SUBTYPES',
     '-selectedSubTypes',
     '[WorkClass RoutingRule TransactionClass ServiceClass]',
     '-options', '[[PortablePropertiesFile true]]'],
    OUTDIR + '/F.props')

# TEST G: bonus - try a different approach using AdminConfig.show
# This bypasses extractConfigProperties entirely
print ""
print "------------------------------------------------------------"
print "TEST G: AdminConfig.list('Node') filtered by name"
print "------------------------------------------------------------"
try:
    nodes = AdminConfig.list('Node')
    found = 0
    for line in nodes.splitlines():
        if NODE in line:
            print "  Found node entry: %s" % line
            # Try AdminConfig.show on it
            cfgId = line
            try:
                attrs = AdminConfig.show(cfgId)
                print "  AdminConfig.show succeeded, length=%d chars" % \
                    len(attrs)
                # Save first 500 chars to file
                f = open(OUTDIR + '/G_show.txt', 'w')
                try:
                    f.write(attrs)
                finally:
                    f.close()
                print "  Saved to %s/G_show.txt" % OUTDIR
                found = 1
            except java.lang.Throwable, jt:
                print "  AdminConfig.show failed: %s" % str(jt)
            except Exception, e:
                print "  AdminConfig.show failed: %s" % str(e)
            break
    if not found:
        print "  No node entry matched %s" % NODE
except java.lang.Throwable, jt:
    print "  Failed: %s" % str(jt)
except Exception, e:
    print "  Failed: %s" % str(e)


print ""
print "============================================================"
print "Files in %s:" % OUTDIR
print "============================================================"
files = os.listdir(OUTDIR)
files.sort()
for f in files:
    full = os.path.join(OUTDIR, f)
    if os.path.isfile(full):
        print "  %s (%d bytes)" % (f, os.path.getsize(full))

print ""
print "Done. Please share the entire output above."
