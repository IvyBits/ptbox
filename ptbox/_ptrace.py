import ctypes

libc = ctypes.CDLL('libc.so.6', use_errno=True)
ptrace = libc.ptrace

# ptrace constants
PTRACE_TRACEME = 0
PTRACE_PEEKDATA = 2
PTRACE_GETREGS = 12
PTRACE_SYSCALL = 24
PTRACE_ATTACH = 8
PTRACE_CONT = 7
PTRACE_PEEKUSR = 3

libc = ctypes.CDLL('libc.so.6', use_errno=True)
ptrace = libc.ptrace
