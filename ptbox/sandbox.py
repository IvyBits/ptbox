import os
import subprocess
import sys
import time
import resource
import argparse
import re
from signal import *
from ptbox import *


class nix_Process(object):
    def __init__(self, chained, memory_limit):
        self._chained = chained
        self.stdout = chained.stdout
        self.stdin = chained.stdin
        self.usages = None
        self.returncode = None
        self.memory_limit = memory_limit

    def __getattr__(self, name):
        if name in ["wait", "send_signal", "terminate", "kill"]:
            return getattr(self._chained, name)
        return object.__getattribute__(self, name)

    def poll(self):
        a = self._chained.poll()
        if a is not None:
            self.returncode = self._get_usages()[-1]
            return self.returncode
        return None

    def _get_usages(self):
        """
            Returns an array containing [bool tle, int max memory usage (kb), int runtime, int error code]
        """
        if not self.usages:
            self.usages = map(eval, self._chained.stderr.readline().split())
        return self.usages

    def get_tle(self):
        return self._get_usages()[0]

    def get_mle(self):
        return self._get_usages()[1] > self.memory_limit

    def get_execution_time(self):
        return self._get_usages()[2]

    def get_max_memory(self):
        return self._get_usages()[1]


def execute(args, time=None, memory=None, filesystem=None):
    p_args = [sys.executable, __file__]
    if time:
        p_args += ["-t", str(time)]
    if memory:
        p_args += ["-m", str(memory)]
    if filesystem:
        p_args += ["-fs", ':'.join(filesystem)]

    p_args.append("--")
    p_args += args
    process = subprocess.Popen(p_args,
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    return nix_Process(process, memory)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Runs and monitors a process' usage stats on *nix systems")
    parser.add_argument("child_args", nargs="+", help="The child process path followed by arguments; relative allowed")
    parser.add_argument("-t", "--time", type=float, help="Time to limit process to, in seconds")
    parser.add_argument("-m", "--memory", type=int, help="Memory to limit process to, in kb")
    parser.add_argument("-fs", "--filesystem-access", help="':'-delimited directory masks; regex allowed")
    parsed = parser.parse_args()

    child = parsed.child_args[0]
    child_args = parsed.child_args

    fs_jail = [re.compile(mask) for mask in
               (parsed.filesystem_access.split(':') if parsed.filesystem_access else ['.*'])]

    proc_mem = None

    @syscall
    def do_allow(pid):
        return True

    @syscall
    def do_write(pid):
        fd = arg0(pid).as_int
        # Only allow writing to stdout & stderr
        print fd,
        return fd == 1 or fd == 2


    execve_count = 0

    @unsafe_syscall
    def do_execve(pid):
        global execve_count
        execve_count += 1
        if execve_count > 2:
            return False
        return True

    def __do_access(pid):
        global proc_mem
        try:
            addr = arg0(pid).as_uint
            print "(%d)" % addr,
            if addr > 0:
                if not proc_mem:
                    proc_mem = open("/proc/%d/mem" % pid, "rb")
                proc_mem.seek(addr, 0)
                buf = ''
                page = (addr + 4096) // 4096 * 4096 - addr
                while True:
                    buf += proc_mem.read(page)
                    if '\0' in buf:
                        buf = buf[:buf.index('\0')]
                        break
                    page = 4096
                print buf,
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

    # @formatter:off
    proxied_syscalls = {
        sys_execve:             do_execve,
        sys_read:               do_allow,
        sys_write:              do_write,
        sys_open:               do_open,
        sys_access:             do_access,
        sys_close:              do_allow,
        sys_stat:               do_allow,
        sys_fstat:              do_allow,
        sys_mmap:               do_allow,
        sys_mprotect:           do_allow,
        sys_munmap:             do_allow,
        sys_brk:                do_allow,
        sys_fcntl:              do_allow,
        sys_arch_prctl:         do_allow,
        sys_set_tid_address:    do_allow,
        sys_set_robust_list:    do_allow,
        sys_futex:              do_allow,
        sys_rt_sigaction:       do_allow,
        sys_rt_sigprocmask:     do_allow,
        sys_getrlimit:          do_allow,
        sys_ioctl:              do_allow,
        sys_readlink:           do_allow,
        sys_getcwd:             do_allow,
        sys_geteuid:            do_allow,
        sys_getuid:             do_allow,
        sys_getegid:            do_allow,
        sys_getgid:             do_allow,
        sys_lstat:              do_allow,
        sys_openat:             do_allow,
        sys_getdents:           do_allow,
        sys_lseek:              do_allow,

        sys_clone:              do_allow,
        sys_exit_group:         do_allow,
    }
    # @formatter:on

    rusage = None
    status = None

    mem = None
    pid = os.fork()
    if not pid:
        if parsed.memory:
            resource.setrlimit(resource.RLIMIT_AS, (32 * 1024 * 1024,) * 2)
        ptrace(PTRACE_TRACEME, 0, None, None)
        # Merge the stderr (2) into stdout (1) so that the execute
        # may be able to return usage stats through stderr
        os.dup2(1, 2)
        # Close all file descriptors that are not standard
        os.closerange(3, os.sysconf("SC_OPEN_MAX"))
        os.kill(os.getpid(), SIGSTOP)
        # Replace current process with the child process
        # This call does not return
        os.execvp(child, child_args)
        # Unless it does, of course, in which case you're screwed
        # We don't cover this in the warranty
        #  When you reach here, you are screwed
        # As much as being handed control of a MySQL server without
        # ANY SQL knowledge or docs. ENJOY.
        os._exit(3306)
    else:
        start = time.time()
        i = 0
        in_syscall = False
        while True:
            _, status, rusage = os.wait4(pid, 0)

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

                    if call in proxied_syscalls:
                        if not proxied_syscalls[call](pid):
                            os.kill(pid, SIGKILL)
                            print
                            print "You're doing Something Bad"
                            break
                        print
                        continue
                    else:
                        print
                        raise Exception(call)

            ptrace(PTRACE_SYSCALL, pid, None, None)

        duration = time.time() - start
        if status is None:  # TLE
            os.kill(pid, SIGKILL)
            _, status, rusage = os.wait4(pid, 0)
            print 'Time Limit Exceeded'
        print rusage.ru_maxrss, 'KB of RAM'
        print 'Execution time: %.3f seconds' % duration
        print 'Return:', os.WEXITSTATUS(status)

