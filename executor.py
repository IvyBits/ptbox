from ptbox import sandbox
from ptbox import chroot

debugger = chroot.CHROOTProcessDebugger(filesystem=["usr/bin/python", ".*\.[so|py]", "/usr/lib/python", "/etc/.*"])

process = sandbox.execute(["/usr/bin/python", "test.py"], debugger=debugger)