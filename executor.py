from ptbox import sandbox
import sys
import os

process = sandbox.execute(["/usr/bin/python", "test.py"],
                          filesystem=["usr/bin/python", ".*\.[so|py]", "/usr/lib/python", "/etc/.*"])
print process.wait()
print "----"
print >> sys.stdout, process.stdout.read()
print >> sys.stderr, process.stderr.read()