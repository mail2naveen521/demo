###############################################################################
# diag_odr2.py  (minimal version - guaranteed Jython 2.1 safe)
#
# Tests 6 ways to extract OdrNode1 to find what works.
# No conditional expressions, no sorted(), no fancy syntax.
#
# Run with:
#   $DMGR_PROFILE/bin/wsadmin.sh -lang jython -f diag_odr2.py
###############################################################################

import sys
import os

NODE = 'OdrNode1'
OUTDIR = '/tmp/diag_odr2'

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
    try:
        AdminTask.extractConfigProperties(args)
        if os.path.exists(outFile):
            sz = os.path.getsize(outFile)
            print "  RESULT: SUCCESS (%d bytes)" % sz
        else:
            print "  RESULT: returned but no file"
    except Exception, e:
        print "  RESULT: FAILED"
        print "    class: %s" % e.__class__.__name__
        print "    msg: %s" % str(e)


# CHECK: nodeagent reachable?
print "============================================================"
print "CHECK 1: nodeagent reachable?"
print "============================================================"
try:
    naMBean = AdminControl.completeObjectName(
        'type=NodeAgent,node=%s,*' % NODE)
    if naMBean:
        naMBean = naMBean.strip()
    if naMBean:
        print "  YES - nodeagent MBean: %s" % naMBean
    else:
        print "  NO - nodeagent not reachable"
except Exception, e:
    print "  ERROR checking: %s" % str(e)

# CHECK: what servers on this node?
print ""
print "============================================================"
print "CHECK 2: servers on %s" % NODE
print "============================================================"
firstServer = ''
try:
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
            if not firstServer:
                firstServer = sn
                firstServerType = stype
except Exception, e:
    print "  ERROR: %s" % str(e)


# Build test args
nodeScope_cd = 'Cell=%s,Node=%s' % (cellName, NODE)

# TEST A: simplest possible - node scope, no options
runTest('A', 'Node scope, NO -options',
    ['-propertiesFileName', OUTDIR + '/A.props',
     '-configData', nodeScope_cd],
    OUTDIR + '/A.props')

# TEST B: node scope WITH options
runTest('B', 'Node scope WITH PortablePropertiesFile',
    ['-propertiesFileName', OUTDIR + '/B.props',
     '-configData', nodeScope_cd,
     '-options', '[[PortablePropertiesFile true]]'],
    OUTDIR + '/B.props')

# TEST C: server scope (skip node level)
if firstServer:
    serverScope_cd = 'Cell=%s,Node=%s,Server=%s' % \
        (cellName, NODE, firstServer)
    runTest('C', 'Server scope (%s, %s)' % (firstServer, firstServerType),
        ['-propertiesFileName', OUTDIR + '/C.props',
         '-configData', serverScope_cd],
        OUTDIR + '/C.props')
else:
    print ""
    print "TEST C: SKIPPED - no non-agent server found"

# TEST D: node scope, filter to common types
runTest('D', 'Node scope, SELECTED_SUBTYPES (common types)',
    ['-propertiesFileName', OUTDIR + '/D.props',
     '-configData', nodeScope_cd,
     '-filterMechanism', 'SELECTED_SUBTYPES',
     '-selectedSubTypes',
     '[Variable JavaProcessDef Property NameSpaceBinding]'],
    OUTDIR + '/D.props')

# TEST E: D + options
runTest('E', 'Node scope, SELECTED_SUBTYPES + portable option',
    ['-propertiesFileName', OUTDIR + '/E.props',
     '-configData', nodeScope_cd,
     '-filterMechanism', 'SELECTED_SUBTYPES',
     '-selectedSubTypes',
     '[Variable JavaProcessDef Property NameSpaceBinding]',
     '-options', '[[PortablePropertiesFile true]]'],
    OUTDIR + '/E.props')

# TEST F: node scope EXCLUDING ODR-specific types
runTest('F', 'Node scope, NO_SUBTYPES (exclude ODR types)',
    ['-propertiesFileName', OUTDIR + '/F.props',
     '-configData', nodeScope_cd,
     '-filterMechanism', 'NO_SUBTYPES',
     '-selectedSubTypes',
     '[WorkClass RoutingRule TransactionClass ServiceClass]',
     '-options', '[[PortablePropertiesFile true]]'],
    OUTDIR + '/F.props')

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
print "Done. Please share this entire output."
