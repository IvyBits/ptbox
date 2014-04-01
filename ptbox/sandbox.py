import os
import time
import resource
import gc
from signal import *
import threading
from platform import architecture

from ._ptrace import *


def _find_exe(path):
    if os.path.isabs(path):
        return path
    if os.sep in path:
        return os.path.abspath(path)
    for dir in os.environ.get('PATH', os.defpath).split(os.pathsep):
        p = os.path.join(dir, path)
        if os.access(p, os.X_OK):
            return p
    raise OSError()


class SecurePopen(object):
    def __init__(self, args, debugger, time, memory):
        self._args = args
        self._child = _find_exe(self._args[0])
        self._debugger = debugger
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

    @property
    def bitness(self):
        return int(architecture(self._child)[0][:2])

    def __shocker(self):
        self._started.wait()
        time.sleep(self._time)
        if self.returncode is None:
            os.kill(self._pid, SIGKILL)
            self._tle = True

    def __spawn_execute(self):
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
            os.execv(self._child, child_args)
            # Unless it does, of course, in which case you're screwed
            # We don't cover this in the warranty
            # When you reach here, you are screwed
            # As much as being handed control of a MySQL server without
            # ANY SQL knowledge or docs. ENJOY.
            os._exit(3306)
        else:
            if gc_enabled:
                gc.enable()

            self._debugger.pid = pid
            if self.bitness == 64:
                import _ptrace64 as _ptrace
            else:
                import _ptrace32 as _ptrace
            self._debugger.arg0 = lambda: _ptrace.arg0(pid)
            self._debugger.arg1 = lambda: _ptrace.arg1(pid)
            self._debugger.arg2 = lambda: _ptrace.arg2(pid)
            self._debugger.arg3 = lambda: _ptrace.arg3(pid)
            self._debugger.arg4 = lambda: _ptrace.arg4(pid)
            self._debugger.arg5 = lambda: _ptrace.arg5(pid)
            self._debugger.get_syscall_number = lambda: _ptrace.get_syscall_number(pid)

            reverse_syscalls = dict((v, k) for k, v in _ptrace.syscalls.iteritems())
            self._debugger.reverse_syscalls = reverse_syscalls

            # Define all syscalls as variables
            for call, id in _ptrace.syscalls.iteritems():
                setattr(self._debugger, call, id)

            syscall_proxies = self._debugger.get_handlers()

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
                        call = _ptrace.get_syscall_number(pid)

                        print reverse_syscalls[call],

                        if call in syscall_proxies:
                            if not syscall_proxies[call]():
                                os.kill(pid, SIGKILL)
                                print
                                print "You're doing Something Bad"
                            print
                            continue
                        else:
                            print syscall_proxies
                            raise Exception(call)

                ptrace(PTRACE_SYSCALL, pid, None, None)

            self._duration = time.time() - start
            ret = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -os.WTERMSIG(status)
            print self._rusage.ru_maxrss, 'KB of RAM'
            print 'Execution time: %.3f seconds' % self._duration
            print 'Return:', ret
            self._returncode = ret
            self._died.set()


def debug(args, debugger):
    return execute(args, debugger)


def execute(args, debugger, time=None, memory=None):
    return SecurePopen(args, debugger, time, memory)
