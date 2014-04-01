import os
from signal import *

if True:
    from ._ptrace64 import *
else:
    from ._ptrace32 import *

reverse_syscalls = dict((v, k) for k, v in syscalls.iteritems())

# Define all syscalls as variables
for call, id in syscalls.iteritems():
    vars()[call] = id


def syscall(func):
    def delegate(pid, *args, **kwargs):
        if func(pid, *args, **kwargs):
            ptrace(PTRACE_SYSCALL, pid, None, None)
            return True
        return False

    return delegate


def unsafe_syscall(func):
    """
        ptrace recieves notifications prior to the kernel reading the memory pointed to by the registers.
        It is theoretically possible to modify a pointer after ptbox finishes validation but
        before the memory is actually accessed, given a multiprocess task.

        Hence, here we stop all child tasks (SIGSTOP), execute the syscall, then resume all tasks (SIGCONT).
    """

    def halter(pid, *args, **kwargs):
        tasks = map(int, os.listdir("/proc/%d/task" % os.getpid()))
        tasks.remove(os.getpid())
        if 0 and tasks:
            for task in tasks:
                os.kill(task, SIGSTOP)
        ret = func(pid, *args, **kwargs)
        if ret:
            ptrace(PTRACE_SYSCALL, pid, None, None)
        if 0 and tasks:
            for task in tasks:
                os.kill(task, SIGCONT)
        return ret

    return halter