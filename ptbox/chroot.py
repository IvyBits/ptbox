import os
import re
from signal import *
from _ptrace import *
from __init__ import *


class CHROOTProcessDebugger(ProcessDebugger):
    def __init__(self, filesystem=None):
        super(CHROOTProcessDebugger, self).__init__()
        self.fs_jail = [re.compile(mask) for mask in (filesystem if filesystem else ['.*'])]
        self.execve_count = 0

    def get_handlers(self):
        return {
            self.sys_execve: self.do_execve,
            self.sys_read: self.do_allow,
            self.sys_write: self.do_write,
            self.sys_open: self.do_open,
            self.sys_access: self.do_access,
            self.sys_close: self.do_allow,
            self.sys_stat: self.do_allow,
            self.sys_fstat: self.do_allow,
            self.sys_mmap: self.do_allow,
            self.sys_mprotect: self.do_allow,
            self.sys_munmap: self.do_allow,
            self.sys_brk: self.do_allow,
            self.sys_fcntl: self.do_allow,
            self.sys_arch_prctl: self.do_allow,
            self.sys_set_tid_address: self.do_allow,
            self.sys_set_robust_list: self.do_allow,
            self.sys_futex: self.do_allow,
            self.sys_rt_sigaction: self.do_allow,
            self.sys_rt_sigprocmask: self.do_allow,
            self.sys_getrlimit: self.do_allow,
            self.sys_ioctl: self.do_allow,
            self.sys_readlink: self.do_allow,
            self.sys_getcwd: self.do_allow,
            self.sys_geteuid: self.do_allow,
            self.sys_getuid: self.do_allow,
            self.sys_getegid: self.do_allow,
            self.sys_getgid: self.do_allow,
            self.sys_lstat: self.do_allow,
            self.sys_openat: self.do_allow,
            self.sys_getdents: self.do_allow,
            self.sys_lseek: self.do_allow,

            self.sys_clone: self.do_allow,
            self.sys_exit_group: self.do_allow,
        }

    @syscall
    def do_allow(self):
        return True

    @syscall
    def do_write(self):
        fd = self.arg0().as_int
        # Only allow writing to stdout & stderr
        print fd,
        return fd == 1 or fd == 2


    @unsafe_syscall
    def do_execve(self):
        self.execve_count += 1
        if self.execve_count > 2:
            return False
        return True

    def __do_access(self):
        try:
            addr = self.arg0().as_uint64
            print "(%d)" % addr,
            if addr > 0:
                #proc_mem = open("/proc/%d/mem" % pid, "rb")

                #proc_mem.seek(addr, 0)
                proc_mem = os.open('/proc/%d/mem' % self.pid, os.O_RDONLY)
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
                for mask in self.fs_jail:
                    if mask.match(buf):
                        break
                else:
                    return False

        except:
            import traceback

            traceback.print_exc()
        return True

    @unsafe_syscall
    def do_access(self):
        return self.__do_access()

    @unsafe_syscall
    def do_open(self):
        flags = self.arg1().as_int
        print flags, oct(self.arg2().as_uint)
        return self.__do_access()