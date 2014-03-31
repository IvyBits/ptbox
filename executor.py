from ptbox import sandbox
import sys

process = sandbox.execute(["/usr/bin/python", "test.py"],
                          filesystem=["usr/bin/python", ".*\.[so|py]", "/usr/lib/python"])
process.poll()
print >> sys.stderr, ''.join(process._chained.stderr.readlines())
print >> sys.stdout, ''.join(process._chained.stdout.readlines())