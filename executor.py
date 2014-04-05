from ptbox import sandbox
from ptbox import chroot

PYTHON_FS = ["usr/bin/python", ".*\.[so|py]", "/usr/lib/python", "/etc/.*"]
RUBY_FS = ["usr/bin/ruby", ".*\.[so|rb]"]
JAVA_FS = ["/usr/bin/java", ".\.[so|jar]"]

debugger = chroot.CHROOTProcessDebugger(filesystem=RUBY_FS)

process = sandbox.execute(["/usr/bin/ruby", "test.rb"], debugger=debugger)
print "----"
print process.stderr.read()
print process.stdout.read()