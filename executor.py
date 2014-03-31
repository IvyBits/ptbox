from ptbox import sandbox

process = sandbox.execute(["/usr/bin/python", "test.py"], filesystem="usr/bin/python:.*\.[so|py]:/usr/lib/python".split(":"))
process.poll()
print ''.join(process._chained.stderr.readlines())