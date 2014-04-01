from ptbox import sandbox
import sys
import os
from ptbox import chroot

debugger = chroot.CHROOTProcessDebugger(filesystem=["usr/bin/python", ".*\.[so|py]", "/usr/lib/python", "/etc/.*"])

process = sandbox.execute(["/usr/bin/python", "test.py"], debugger=debugger)
print process.wait()
print "----"
print >> sys.stdout, process.stdout.read()
print >> sys.stderr, process.stderr.read()