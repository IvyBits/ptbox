if True:
    from ._ptrace64 import *
else:
    from ._ptrace32 import *

reverse_syscalls = dict((v, k) for k, v in syscalls.iteritems())

# Define all syscalls as variables
for call, id in syscalls.iteritems():
    vars()[call] = id