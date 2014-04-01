from ptbox import sandbox
import sys
import os

process = sandbox.execute(["/usr/bin/python", "test.py"],
                          filesystem=["usr/bin/python", ".*\.[so|py]", "/usr/lib/python", "/etc/.*"])
process.poll()

print >> sys.stdout, ''.join(process.stdout.readlines())
print >> sys.stderr, ''.join(process.stderr.readlines())