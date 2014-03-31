from ptbox import sandbox
import sys
import os

'''print os.listdir("/proc/%d/task" % os.getpid())
print os.getpid()'''



process = sandbox.execute(["/usr/bin/python", "test.py"],
                          filesystem=["usr/bin/python", ".*\.[so|py]", "/usr/lib/python"])
process.poll()
print >> sys.stdout, ''.join(process._chained.stdout.readlines())
print >> sys.stderr, ''.join(process._chained.stderr.readlines())