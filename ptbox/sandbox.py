import os
import subprocess
import sys
import time
import resource
import argparse
import re
import gc
from signal import *
from ptbox import *
import threading


class SecurePopen(object):
    def __init__(self, args, handlers, time, memory):
        self._args = args
        self._handlers = handlers
        self._time = time
        self._memory = memory
        self._returncode = None
        self._tle = False
        self._pid = None
        self._rusage = None
        self._duration = None

        self._stdin_, self._stdin = os.pipe()
        self._stdout, self._stdout_ = os.pipe()
        self._stderr, self._stderr_ = os.pipe()
        self.stdin = os.fdopen(self._stdin, 'w')
        self.stdout = os.fdopen(self._stdout, 'r')
        self.stderr = os.fdopen(self._stderr, 'r')

        self._started = threading.Event()
        self._died = threading.Event()
        self._worker = threading.Thread(target=self.__spawn_execute)
        self._worker.start()
        if time:
            self._shocker = threading.Thread(target=self.__shocker)
            self._shocker.start()

    @property
    def returncode(self):
        return self._returncode

    def wait(self):
        self._died.wait()
        return self._returncode

    def poll(self):
        return self._returncode

    @property
    def max_memory(self):
        if self._rusage is not None:
            return self._rusage.ru_maxrss

    @property
    def execution_time(self):
        return self._duration

    @property
    def mle(self):
        if self._memory is None:
            return False
        if self._rusage is not None:
            return self._rusage.ru_maxrss > self._memory

    @property
    def tle(self):
        return self._tle

    def __shocker(self):
        self._started.wait()
        time.sleep(self._time)
        if self.returncode is None:
            os.kill(self._pid, SIGKILL)
            self._tle = True

    def __spawn_execute(self):
        child = self._args[0]
        child_args = self._args

        status = None
        gc_enabled = gc.isenabled()
        try:
            gc.disable()
            pid = os.fork()
        except:
            if gc_enabled:
                gc.enable()
            raise
        if not pid:
            if self._memory:
                resource.setrlimit(resource.RLIMIT_AS, (self._memory * 1024 + 16 * 1024 * 1024,) * 2)
            os.dup2(self._stdin_, 0)
            os.dup2(self._stdout_, 1)
            os.dup2(self._stderr_, 2)
            ptrace(PTRACE_TRACEME, 0, None, None)
            # Close all file descriptors that are not standard
            os.closerange(3, os.sysconf("SC_OPEN_MAX"))
            os.kill(os.getpid(), SIGSTOP)
            # Replace current process with the child process
            # This call does not return
            os.execvp(child, child_args)
            # Unless it does, of course, in which case you're screwed
            # We don't cover this in the warranty
            # When you reach here, you are screwed
            # As much as being handed control of a MySQL server without
            # ANY SQL knowledge or docs. ENJOY.
            os._exit(3306)
        else:
            if gc_enabled:
                gc.enable()

            os.close(self._stdin_)
            os.close(self._stdout_)
            os.close(self._stderr_)

            self._pid = pid
            self._started.set()

            start = time.time()
            i = 0
            in_syscall = False
            while True:
                _, status, self._rusage = os.wait4(pid, 0)

                if os.WIFEXITED(status):
                    print "Exited"
                    break

                if os.WIFSIGNALED(status):
                    break

                if os.WSTOPSIG(status) == SIGTRAP:
                    in_syscall = not in_syscall
                    if not in_syscall:
                        call = get_syscall_number(pid)

                        print reverse_syscalls[call],

                        if call in self._handlers:
                            if not self._handlers[call](pid):
                                os.kill(pid, SIGKILL)
                                print
                                print "You're doing Something Bad"
                            print
                            continue
                        else:
                            raise Exception(call)

                ptrace(PTRACE_SYSCALL, pid, None, None)

            self._duration = time.time() - start
            ret = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -os.WTERMSIG(status)
            print self._rusage.ru_maxrss, 'KB of RAM'
            print 'Execution time: %.3f seconds' % self._duration
            print 'Return:', ret
            self._returncode = ret
            self._died.set()


def execute(args, time=None, memory=None, filesystem=None):
    fs_jail = [re.compile(mask) for mask in
               (filesystem if filesystem else ['.*'])]

    @syscall
    def do_allow(pid):
        return True

    @syscall
    def do_write(pid):
        fd = arg0(pid).as_int
        # Only allow writing to stdout & stderr
        print fd,
        return fd == 1 or fd == 2


    execve_count = [0]

    @unsafe_syscall
    def do_execve(pid):
        execve_count[0] += 1
        if execve_count[0] > 2:
            return False
        return True

    def __do_access(pid):
        try:
            addr = arg0(pid).as_uint64
            print "(%d)" % addr,
            if addr > 0:
                #proc_mem = open("/proc/%d/mem" % pid, "rb")

                #proc_mem.seek(addr, 0)
                proc_mem = os.open('/proc/%d/mem' % pid, os.O_RDONLY)
                os.lseek(proc_mem, addr, os.SEEK_SET)
                buf = ''
                page = (addr + 4096) // 4096 * 4096 - addr
                while True:
                    #buf += proc_mem.read(page)
                    buf += os.read(proc_mem, page)
                    if '\0' in buf:
                        buf = buf[:buf.index('\0')]
                        break
                    page = 4096
                print buf,
                os.close(proc_mem)
                for mask in fs_jail:
                    if mask.match(buf):
                        break
                else:
                    return False

        except:
            import traceback

            traceback.print_exc()
        return True

    @unsafe_syscall
    def do_access(pid):
        return __do_access(pid)

    @unsafe_syscall
    def do_open(pid):
        mode = arg2(pid).as_int
        if mode:
            print mode,
            # TODO: kill
        return __do_access(pid)

    proxied_syscalls = {
        sys_execve: do_execve,
        sys_read: do_allow,
        sys_write: do_write,
        sys_open: do_open,
        sys_access: do_access,
        sys_close: do_allow,
        sys_stat: do_allow,
        sys_fstat: do_allow,
        sys_mmap: do_allow,
        sys_mprotect: do_allow,
        sys_munmap: do_allow,
        sys_brk: do_allow,
        sys_fcntl: do_allow,
        sys_arch_prctl: do_allow,
        sys_set_tid_address: do_allow,
        sys_set_robust_list: do_allow,
        sys_futex: do_allow,
        sys_rt_sigaction: do_allow,
        sys_rt_sigprocmask: do_allow,
        sys_getrlimit: do_allow,
        sys_ioctl: do_allow,
        sys_readlink: do_allow,
        sys_getcwd: do_allow,
        sys_geteuid: do_allow,
        sys_getuid: do_allow,
        sys_getegid: do_allow,
        sys_getgid: do_allow,
        sys_lstat: do_allow,
        sys_openat: do_allow,
        sys_getdents: do_allow,
        sys_lseek: do_allow,

        sys_clone: do_allow,
        sys_exit_group: do_allow,
    }
    return SecurePopen(args, proxied_syscalls, time, memory)
