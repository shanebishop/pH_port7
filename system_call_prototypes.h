/*
system_call_prototypes.h file

Currently used signums - 0 through 383
*/

#include <linux/aio_abi.h>

// Grab syscalls
#ifdef __i386__
#define __SYSCALL_I386(nr, sym, qual) [nr] = 1,
static char syscalls[] = {
#include <asm/syscalls_32.h>
};
#else
#define __SYSCALL_64(nr, sym, qual) [nr] = 1,
static char syscalls[] = {
#include <asm/syscalls_64.h>
};
#endif

// process_syscall prototype
int process_syscall(long);

// jsys_execve prototype
static long jsys_execve(const char __user *,
	const char __user *const __user *,
	const char __user *const __user *);

// jsys_exit prototype
static long jsys_exit(int);

// jsys_exit_group prototype
static long jsys_exit_group(int);

// Global variables
//#define num_syscalls (sizeof(syscalls) / sizeof(syscalls[0]))
//static struct jprobe jprobes_array[num_syscalls];

// JProbe functions
static long jsys32_quotactl(unsigned int cmd, const char __user *special,
			       qid_t id, void __user *addr) { process_syscall(0); jprobe_return(); return 0; }
static long jsys_time(time_t __user *tloc) { process_syscall(1); jprobe_return(); return 0; }
static long jsys_stime(time_t __user *tptr) { process_syscall(2); jprobe_return(); return 0; }
static long jsys_gettimeofday(struct timeval __user *tv,
				struct timezone __user *tz) { process_syscall(3); jprobe_return(); return 0; }
static long jsys_settimeofday(struct timeval __user *tv,
				struct timezone __user *tz) { process_syscall(4); jprobe_return(); return 0; }
static long jsys_adjtimex(struct timex __user *txc_p) { process_syscall(5); jprobe_return(); return 0; }

static long jsys_times(struct tms __user *tbuf) { process_syscall(6); jprobe_return(); return 0; }

static long jsys_gettid(void) { process_syscall(7); jprobe_return(); return 0; }
static long jsys_nanosleep(struct timespec __user *rqtp, struct timespec __user *rmtp) { process_syscall(8); jprobe_return(); return 0; }
static long jsys_alarm(unsigned int seconds) { process_syscall(9); jprobe_return(); return 0; }
static long jsys_getpid(void) { process_syscall(10); jprobe_return(); return 0; }
static long jsys_getppid(void) { process_syscall(11); jprobe_return(); return 0; }
static long jsys_getuid(void) { process_syscall(12); jprobe_return(); return 0; }
static long jsys_geteuid(void) { process_syscall(13); jprobe_return(); return 0; }
static long jsys_getgid(void) { process_syscall(14); jprobe_return(); return 0; }
static long jsys_getegid(void) { process_syscall(15); jprobe_return(); return 0; }
static long jsys_getresuid(uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid) { process_syscall(16); jprobe_return(); return 0; }
static long jsys_getresgid(gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid) { process_syscall(17); jprobe_return(); return 0; }
static long jsys_getpgid(pid_t pid) { process_syscall(18); jprobe_return(); return 0; }
static long jsys_getpgrp(void) { process_syscall(19); jprobe_return(); return 0; }
static long jsys_getsid(pid_t pid) { process_syscall(20); jprobe_return(); return 0; }
static long jsys_getgroups(int gidsetsize, gid_t __user *grouplist) { process_syscall(21); jprobe_return(); return 0; }

static long jsys_setregid(gid_t rgid, gid_t egid) { process_syscall(22); jprobe_return(); return 0; }
static long jsys_setgid(gid_t gid) { process_syscall(23); jprobe_return(); return 0; }
static long jsys_setreuid(uid_t ruid, uid_t euid) { process_syscall(24); jprobe_return(); return 0; }
static long jsys_setuid(uid_t uid) { process_syscall(25); jprobe_return(); return 0; }
static long jsys_setresuid(uid_t ruid, uid_t euid, uid_t suid) { process_syscall(26); jprobe_return(); return 0; }
static long jsys_setresgid(gid_t rgid, gid_t egid, gid_t sgid) { process_syscall(27); jprobe_return(); return 0; }
static long jsys_setfsuid(uid_t uid) { process_syscall(28); jprobe_return(); return 0; }
static long jsys_setfsgid(gid_t gid) { process_syscall(29); jprobe_return(); return 0; }
static long jsys_setpgid(pid_t pid, pid_t pgid) { process_syscall(30); jprobe_return(); return 0; }
static long jsys_setsid(void) { process_syscall(31); jprobe_return(); return 0; }
static long jsys_setgroups(int gidsetsize, gid_t __user *grouplist) { process_syscall(32); jprobe_return(); return 0; }

static long jsys_acct(const char __user *name) { process_syscall(33); jprobe_return(); return 0; }
static long jsys_capget(cap_user_header_t header,
				cap_user_data_t dataptr) { process_syscall(34); jprobe_return(); return 0; }
static long jsys_capset(cap_user_header_t header,
				const cap_user_data_t data) { process_syscall(35); jprobe_return(); return 0; }
static long jsys_personality(unsigned int personality) { process_syscall(36); jprobe_return(); return 0; }

static long jsys_sigpending(old_sigset_t __user *set) { process_syscall(37); jprobe_return(); return 0; }
static long jsys_sigprocmask(int how, old_sigset_t __user *set,
				old_sigset_t __user *oset) { process_syscall(38); jprobe_return(); return 0; }
static long jsys_sigaltstack(const struct sigaltstack __user *uss,
				struct sigaltstack __user *uoss) { process_syscall(39); jprobe_return(); return 0; }

static long jsys_getitimer(int which, struct itimerval __user *value) { process_syscall(40); jprobe_return(); return 0; }
static long jsys_setitimer(int which,
				struct itimerval __user *value,
				struct itimerval __user *ovalue) { process_syscall(41); jprobe_return(); return 0; }
static long jsys_timer_create(clockid_t which_clock,
				 struct sigevent __user *timer_event_spec,
				 timer_t __user * created_timer_id) { process_syscall(42); jprobe_return(); return 0; }
static long jsys_timer_gettime(timer_t timer_id,
				struct itimerspec __user *setting) { process_syscall(43); jprobe_return(); return 0; }
static long jsys_timer_getoverrun(timer_t timer_id) { process_syscall(44); jprobe_return(); return 0; }
static long jsys_timer_settime(timer_t timer_id, int flags,
				const struct itimerspec __user *new_setting,
				struct itimerspec __user *old_setting) { process_syscall(45); jprobe_return(); return 0; }
static long jsys_timer_delete(timer_t timer_id) { process_syscall(46); jprobe_return(); return 0; }
static long jsys_clock_settime(clockid_t which_clock,
				const struct timespec __user *tp) { process_syscall(47); jprobe_return(); return 0; }
static long jsys_clock_gettime(clockid_t which_clock,
				struct timespec __user *tp) { process_syscall(48); jprobe_return(); return 0; }
static long jsys_clock_adjtime(clockid_t which_clock,
				struct timex __user *tx) { process_syscall(49); jprobe_return(); return 0; }
static long jsys_clock_getres(clockid_t which_clock,
				struct timespec __user *tp) { process_syscall(50); jprobe_return(); return 0; }
static long jsys_clock_nanosleep(clockid_t which_clock, int flags,
				const struct timespec __user *rqtp,
				struct timespec __user *rmtp) { process_syscall(51); jprobe_return(); return 0; }

static long jsys_nice(int increment) { process_syscall(52); jprobe_return(); return 0; }
static long jsys_sched_setscheduler(pid_t pid, int policy,
					struct sched_param __user *param) { process_syscall(53); jprobe_return(); return 0; }
static long jsys_sched_setparam(pid_t pid,
					struct sched_param __user *param) { process_syscall(54); jprobe_return(); return 0; }
static long jsys_sched_setattr(pid_t pid,
					struct sched_attr __user *attr,
					unsigned int flags) { process_syscall(55); jprobe_return(); return 0; }
static long jsys_sched_getscheduler(pid_t pid) { process_syscall(56); jprobe_return(); return 0; }
static long jsys_sched_getparam(pid_t pid,
					struct sched_param __user *param) { process_syscall(57); jprobe_return(); return 0; }
static long jsys_sched_getattr(pid_t pid,
					struct sched_attr __user *attr,
					unsigned int size,
					unsigned int flags) { process_syscall(58); jprobe_return(); return 0; }
static long jsys_sched_setaffinity(pid_t pid, unsigned int len,
					unsigned long __user *user_mask_ptr) { process_syscall(59); jprobe_return(); return 0; }
static long jsys_sched_getaffinity(pid_t pid, unsigned int len,
					unsigned long __user *user_mask_ptr) { process_syscall(60); jprobe_return(); return 0; }
static long jsys_sched_yield(void) { process_syscall(61); jprobe_return(); return 0; }
static long jsys_sched_get_priority_max(int policy) { process_syscall(62); jprobe_return(); return 0; }
static long jsys_sched_get_priority_min(int policy) { process_syscall(63); jprobe_return(); return 0; }
static long jsys_sched_rr_get_interval(pid_t pid,
					struct timespec __user *interval) { process_syscall(64); jprobe_return(); return 0; }
static long jsys_setpriority(int which, int who, int niceval) { process_syscall(65); jprobe_return(); return 0; }
static long jsys_getpriority(int which, int who) { process_syscall(66); jprobe_return(); return 0; }

static long jsys_shutdown(int i1, int i2) { process_syscall(67); jprobe_return(); return 0; }
static long jsys_reboot(int magic1, int magic2, unsigned int cmd,
				void __user *arg) { process_syscall(68); jprobe_return(); return 0; }
static long jsys_restart_syscall(void) { process_syscall(69); jprobe_return(); return 0; }
static long jsys_kexec_load(unsigned long entry, unsigned long nr_segments,
				struct kexec_segment __user *segments,
				unsigned long flags) { process_syscall(70); jprobe_return(); return 0; }
static long jsys_kexec_file_load(int kernel_fd, int initrd_fd,
				    unsigned long cmdline_len,
				    const char __user *cmdline_ptr,
				    unsigned long flags) { process_syscall(71); jprobe_return(); return 0; }

//static long jsys_exit(int error_code) { process_syscall(72); jprobe_return(); return 0; }
static long jsys_exit_group(int error_code) { process_syscall(73); jprobe_return(); return 0; }
static long jsys_wait4(pid_t pid, int __user *stat_addr,
				int options, struct rusage __user *ru) { process_syscall(74); jprobe_return(); return 0; }
static long jsys_waitid(int which, pid_t pid,
			   struct siginfo __user *infop,
			   int options, struct rusage __user *ru) { process_syscall(75); jprobe_return(); return 0; }
static long jsys_waitpid(pid_t pid, int __user *stat_addr, int options) { process_syscall(76); jprobe_return(); return 0; }
static long jsys_set_tid_address(int __user *tidptr) { process_syscall(77); jprobe_return(); return 0; }
static long jsys_futex(u32 __user *uaddr, int op, u32 val,
			struct timespec __user *utime, u32 __user *uaddr2,
			u32 val3) { process_syscall(78); jprobe_return(); return 0; }

static long jsys_init_module(void __user *umod, unsigned long len,
				const char __user *uargs) { process_syscall(79); jprobe_return(); return 0; }
static long jsys_delete_module(const char __user *name_user,
				unsigned int flags) { process_syscall(80); jprobe_return(); return 0; }

#ifdef CONFIG_OLD_SIGSUSPEND
static long jsys_sigsuspend(old_sigset_t mask) { process_syscall(81); jprobe_return(); return 0; }
#endif

#ifdef CONFIG_OLD_SIGSUSPEND3
static long jsys_sigsuspend(int unused1, int unused2, old_sigset_t mask) { process_syscall(82); jprobe_return(); return 0; }
#endif

static long jsys_rt_sigsuspend(sigset_t __user *unewset, size_t sigsetsize) { process_syscall(83); jprobe_return(); return 0; }

#ifdef CONFIG_OLD_SIGACTION
static long jsys_sigaction(int signum, const struct old_sigaction __user *act,
				struct old_sigaction __user *oldact) { process_syscall(84); jprobe_return(); return 0; }
#endif

#ifndef CONFIG_ODD_RT_SIGACTION
static long jsys_rt_sigaction(int signum,
				 const struct sigaction __user *act,
				 struct sigaction __user *oldact,
				 size_t size) { process_syscall(85); jprobe_return(); return 0; }
#endif
static long jsys_rt_sigprocmask(int how, sigset_t __user *set,
				sigset_t __user *oset, size_t sigsetsize) { process_syscall(86); jprobe_return(); return 0; }
static long jsys_rt_sigpending(sigset_t __user *set, size_t sigsetsize) { process_syscall(87); jprobe_return(); return 0; }
static long jsys_rt_sigtimedwait(const sigset_t __user *uthese,
				siginfo_t __user *uinfo,
				const struct timespec __user *uts,
				size_t sigsetsize) { process_syscall(88); jprobe_return(); return 0; }
static long jsys_rt_tgsigqueueinfo(pid_t tgid, pid_t  pid, int sig,
		siginfo_t __user *uinfo) { process_syscall(89); jprobe_return(); return 0; }
static long jsys_kill(pid_t pid, int sig) { process_syscall(90); jprobe_return(); return 0; }
static long jsys_tgkill(pid_t tgid, pid_t pid, int sig) { process_syscall(91); jprobe_return(); return 0; }
static long jsys_tkill(pid_t pid, int sig) { process_syscall(92); jprobe_return(); return 0; }
static long jsys_rt_sigqueueinfo(pid_t pid, int sig, siginfo_t __user *uinfo) { process_syscall(93); jprobe_return(); return 0; }
static long jsys_sgetmask(void) { process_syscall(94); jprobe_return(); return 0; }
static long jsys_ssetmask(int newmask) { process_syscall(95); jprobe_return(); return 0; }
static long jsys_signal(int sig, __sighandler_t handler) { process_syscall(96); jprobe_return(); return 0; }
static long jsys_pause(void) { process_syscall(97); jprobe_return(); return 0; }

static long jsys_sync(void) { process_syscall(98); jprobe_return(); return 0; }
static long jsys_fsync(unsigned int fd) { process_syscall(99); jprobe_return(); return 0; }
static long jsys_fdatasync(unsigned int fd) { process_syscall(100); jprobe_return(); return 0; }
static long jsys_bdflush(int func, long data) { process_syscall(101); jprobe_return(); return 0; }
static long jsys_mount(char __user *dev_name, char __user *dir_name,
				char __user *type, unsigned long flags,
				void __user *data) { process_syscall(102); jprobe_return(); return 0; }
static long jsys_umount(char __user *name, int flags) { process_syscall(103); jprobe_return(); return 0; }
static long jsys_oldumount(char __user *name) { process_syscall(104); jprobe_return(); return 0; }
static long jsys_truncate(const char __user *path, long length) { process_syscall(105); jprobe_return(); return 0; }
static long jsys_ftruncate(unsigned int fd, unsigned long length) { process_syscall(106); jprobe_return(); return 0; }
static long jsys_stat(const char __user *filename,
			struct __old_kernel_stat __user *statbuf) { process_syscall(107); jprobe_return(); return 0; }
static long jsys_statfs(const char __user * path,
				struct statfs __user *buf) { process_syscall(108); jprobe_return(); return 0; }
static long jsys_statfs64(const char __user *path, size_t sz,
				struct statfs64 __user *buf) { process_syscall(109); jprobe_return(); return 0; }
static long jsys_fstatfs(unsigned int fd, struct statfs __user *buf) { process_syscall(110); jprobe_return(); return 0; }
static long jsys_fstatfs64(unsigned int fd, size_t sz,
				struct statfs64 __user *buf) { process_syscall(111); jprobe_return(); return 0; }
static long jsys_lstat(const char __user *filename,
			struct __old_kernel_stat __user *statbuf) { process_syscall(112); jprobe_return(); return 0; }
static long jsys_fstat(unsigned int fd,
			struct __old_kernel_stat __user *statbuf) { process_syscall(113); jprobe_return(); return 0; }
static long jsys_newstat(const char __user *filename,
				struct stat __user *statbuf) { process_syscall(114); jprobe_return(); return 0; }
static long jsys_newlstat(const char __user *filename,
				struct stat __user *statbuf) { process_syscall(115); jprobe_return(); return 0; }
static long jsys_newfstat(unsigned int fd, struct stat __user *statbuf) { process_syscall(116); jprobe_return(); return 0; }
static long jsys_ustat(unsigned dev, struct ustat __user *ubuf) { process_syscall(117); jprobe_return(); return 0; }
#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
static long jsys_stat64(const char __user *filename,
				struct stat64 __user *statbuf) { process_syscall(118); jprobe_return(); return 0; }
static long jsys_fstat64(unsigned long fd, struct stat64 __user *statbuf) { process_syscall(119); jprobe_return(); return 0; }
static long jsys_lstat64(const char __user *filename,
				struct stat64 __user *statbuf) { process_syscall(120); jprobe_return(); return 0; }
static long jsys_fstatat64(int dfd, const char __user *filename,
			       struct stat64 __user *statbuf, int flag) { process_syscall(121); jprobe_return(); return 0; }
#endif
#if BITS_PER_LONG == 32
static long jsys_truncate64(const char __user *path, loff_t length) { process_syscall(122); jprobe_return(); return 0; }
static long jsys_ftruncate64(unsigned int fd, loff_t length) { process_syscall(123); jprobe_return(); return 0; }
#endif

static long jsys_setxattr(const char __user *path, const char __user *name,
			     const void __user *value, size_t size, int flags) { process_syscall(124); jprobe_return(); return 0; }
static long jsys_lsetxattr(const char __user *path, const char __user *name,
			      const void __user *value, size_t size, int flags) { process_syscall(125); jprobe_return(); return 0; }
static long jsys_fsetxattr(int fd, const char __user *name,
			      const void __user *value, size_t size, int flags) { process_syscall(126); jprobe_return(); return 0; }
static long jsys_getxattr(const char __user *path, const char __user *name,
			     void __user *value, size_t size) { process_syscall(127); jprobe_return(); return 0; }
static long jsys_lgetxattr(const char __user *path, const char __user *name,
			      void __user *value, size_t size) { process_syscall(128); jprobe_return(); return 0; }
static long jsys_fgetxattr(int fd, const char __user *name,
			      void __user *value, size_t size) { process_syscall(129); jprobe_return(); return 0; }
static long jsys_listxattr(const char __user *path, char __user *list,
			      size_t size) { process_syscall(130); jprobe_return(); return 0; }
static long jsys_llistxattr(const char __user *path, char __user *list,
			       size_t size) { process_syscall(131); jprobe_return(); return 0; }
static long jsys_flistxattr(int fd, char __user *list, size_t size) { process_syscall(132); jprobe_return(); return 0; }
static long jsys_removexattr(const char __user *path,
				const char __user *name) { process_syscall(133); jprobe_return(); return 0; }
static long jsys_lremovexattr(const char __user *path,
				 const char __user *name) { process_syscall(134); jprobe_return(); return 0; }
static long jsys_fremovexattr(int fd, const char __user *name) { process_syscall(135); jprobe_return(); return 0; }

static long jsys_brk(unsigned long brk) { process_syscall(136); jprobe_return(); return 0; }
static long jsys_mprotect(unsigned long start, size_t len,
				unsigned long prot) { process_syscall(137); jprobe_return(); return 0; }
static long jsys_mremap(unsigned long addr,
			   unsigned long old_len, unsigned long new_len,
			   unsigned long flags, unsigned long new_addr) { process_syscall(138); jprobe_return(); return 0; }
static long jsys_remap_file_pages(unsigned long start, unsigned long size,
			unsigned long prot, unsigned long pgoff,
			unsigned long flags) { process_syscall(139); jprobe_return(); return 0; }
static long jsys_msync(unsigned long start, size_t len, int flags) { process_syscall(140); jprobe_return(); return 0; }
static long jsys_fadvise64(int fd, loff_t offset, size_t len, int advice) { process_syscall(141); jprobe_return(); return 0; }
static long jsys_fadvise64_64(int fd, loff_t offset, loff_t len, int advice) { process_syscall(142); jprobe_return(); return 0; }
static long jsys_munmap(unsigned long addr, size_t len) { process_syscall(143); jprobe_return(); return 0; }
static long jsys_mlock(unsigned long start, size_t len) { process_syscall(144); jprobe_return(); return 0; }
static long jsys_munlock(unsigned long start, size_t len) { process_syscall(145); jprobe_return(); return 0; }
static long jsys_mlockall(int flags) { process_syscall(146); jprobe_return(); return 0; }
static long jsys_munlockall(void) { process_syscall(147); jprobe_return(); return 0; }
static long jsys_madvise(unsigned long start, size_t len, int behavior) { process_syscall(148); jprobe_return(); return 0; }
static long jsys_mincore(unsigned long start, size_t len,
				unsigned char __user * vec) { process_syscall(149); jprobe_return(); return 0; }

static long jsys_pivot_root(const char __user *new_root,
				const char __user *put_old) { process_syscall(150); jprobe_return(); return 0; }
static long jsys_chroot(const char __user *filename) { process_syscall(151); jprobe_return(); return 0; }
static long jsys_mknod(const char __user *filename, umode_t mode,
				unsigned dev) { process_syscall(152); jprobe_return(); return 0; }
static long jsys_link(const char __user *oldname,
				const char __user *newname) { process_syscall(153); jprobe_return(); return 0; }
static long jsys_symlink(const char __user *old, const char __user *new) { process_syscall(154); jprobe_return(); return 0; }
static long jsys_unlink(const char __user *pathname) { process_syscall(155); jprobe_return(); return 0; }
static long jsys_rename(const char __user *oldname,
				const char __user *newname) { process_syscall(156); jprobe_return(); return 0; }
static long jsys_chmod(const char __user *filename, umode_t mode) { process_syscall(157); jprobe_return(); return 0; }
static long jsys_fchmod(unsigned int fd, umode_t mode) { process_syscall(158); jprobe_return(); return 0; }

static long jsys_fcntl(unsigned int fd, unsigned int cmd, unsigned long arg) { process_syscall(159); jprobe_return(); return 0; }
#if BITS_PER_LONG == 32
static long jsys_fcntl64(unsigned int fd,
				unsigned int cmd, unsigned long arg) { process_syscall(160); jprobe_return(); return 0; }
#endif
static long jsys_pipe(int __user *fildes) { process_syscall(161); jprobe_return(); return 0; }
static long jsys_pipe2(int __user *fildes, int flags) { process_syscall(162); jprobe_return(); return 0; }
static long jsys_dup(unsigned int fildes) { process_syscall(163); jprobe_return(); return 0; }
static long jsys_dup2(unsigned int oldfd, unsigned int newfd) { process_syscall(164); jprobe_return(); return 0; }
static long jsys_dup3(unsigned int oldfd, unsigned int newfd, int flags) { process_syscall(165); jprobe_return(); return 0; }
static long jsys_ioperm(unsigned long from, unsigned long num, int on) { process_syscall(166); jprobe_return(); return 0; }
static long jsys_ioctl(unsigned int fd, unsigned int cmd,
				unsigned long arg) { process_syscall(167); jprobe_return(); return 0; }
static long jsys_flock(unsigned int fd, unsigned int cmd) { process_syscall(168); jprobe_return(); return 0; }
static long jsys_io_setup(unsigned nr_reqs, aio_context_t __user *ctx) { process_syscall(169); jprobe_return(); return 0; }
static long jsys_io_destroy(aio_context_t ctx) { process_syscall(170); jprobe_return(); return 0; }
static long jsys_io_getevents(aio_context_t ctx_id,
				long min_nr,
				long nr,
				struct io_event __user *events,
				struct timespec __user *timeout) { process_syscall(171); jprobe_return(); return 0; }
static long jsys_io_submit(aio_context_t ctx_id, long nr,
				struct iocb __user * __user *iocbpp) { process_syscall(172); jprobe_return(); return 0; }
static long jsys_io_cancel(aio_context_t ctx_id, struct iocb __user *iocb,
			      struct io_event __user *result) { process_syscall(173); jprobe_return(); return 0; }
static long jsys_sendfile(int out_fd, int in_fd,
			     off_t __user *offset, size_t count) { process_syscall(174); jprobe_return(); return 0; }
static long jsys_sendfile64(int out_fd, int in_fd,
			       loff_t __user *offset, size_t count) { process_syscall(175); jprobe_return(); return 0; }
static long jsys_readlink(const char __user *path,
				char __user *buf, int bufsiz) { process_syscall(176); jprobe_return(); return 0; }
static long jsys_creat(const char __user *pathname, umode_t mode) { process_syscall(177); jprobe_return(); return 0; }
static long jsys_open(const char __user *filename,
				int flags, umode_t mode) { process_syscall(178); jprobe_return(); return 0; }
static long jsys_close(unsigned int fd) { process_syscall(179); jprobe_return(); return 0; }
static long jsys_access(const char __user *filename, int mode) { process_syscall(180); jprobe_return(); return 0; }
static long jsys_vhangup(void) { process_syscall(181); jprobe_return(); return 0; }
static long jsys_chown(const char __user *filename,
				uid_t user, gid_t group) { process_syscall(182); jprobe_return(); return 0; }
static long jsys_lchown(const char __user *filename,
				uid_t user, gid_t group) { process_syscall(183); jprobe_return(); return 0; }
static long jsys_fchown(unsigned int fd, uid_t user, gid_t group) { process_syscall(184); jprobe_return(); return 0; }
#ifdef CONFIG_HAVE_UID16
static long jsys_chown16(const char __user *filename,
				old_uid_t user, old_gid_t group) { process_syscall(185); jprobe_return(); return 0; }
static long jsys_lchown16(const char __user *filename,
				old_uid_t user, old_gid_t group) { process_syscall(186); jprobe_return(); return 0; }
static long jsys_fchown16(unsigned int fd, old_uid_t user, old_gid_t group) { process_syscall(187); jprobe_return(); return 0; }
static long jsys_setregid16(old_gid_t rgid, old_gid_t egid) { process_syscall(188); jprobe_return(); return 0; }
static long jsys_setgid16(old_gid_t gid) { process_syscall(189); jprobe_return(); return 0; }
static long jsys_setreuid16(old_uid_t ruid, old_uid_t euid) { process_syscall(190); jprobe_return(); return 0; }
static long jsys_setuid16(old_uid_t uid) { process_syscall(191); jprobe_return(); return 0; }
static long jsys_setresuid16(old_uid_t ruid, old_uid_t euid, old_uid_t suid) { process_syscall(192); jprobe_return(); return 0; }
static long jsys_getresuid16(old_uid_t __user *ruid,
				old_uid_t __user *euid, old_uid_t __user *suid) { process_syscall(193); jprobe_return(); return 0; }
static long jsys_setresgid16(old_gid_t rgid, old_gid_t egid, old_gid_t sgid) { process_syscall(194); jprobe_return(); return 0; }
static long jsys_getresgid16(old_gid_t __user *rgid,
				old_gid_t __user *egid, old_gid_t __user *sgid) { process_syscall(195); jprobe_return(); return 0; }
static long jsys_setfsuid16(old_uid_t uid) { process_syscall(196); jprobe_return(); return 0; }
static long jsys_setfsgid16(old_gid_t gid) { process_syscall(197); jprobe_return(); return 0; }
static long jsys_getgroups16(int gidsetsize, old_gid_t __user *grouplist) { process_syscall(198); jprobe_return(); return 0; }
static long jsys_setgroups16(int gidsetsize, old_gid_t __user *grouplist) { process_syscall(199); jprobe_return(); return 0; }
static long jsys_getuid16(void) { process_syscall(200); jprobe_return(); return 0; }
static long jsys_geteuid16(void) { process_syscall(201); jprobe_return(); return 0; }
static long jsys_getgid16(void) { process_syscall(202); jprobe_return(); return 0; }
static long jsys_getegid16(void) { process_syscall(203); jprobe_return(); return 0; }
#endif

static long jsys_utime(char __user *filename,
				struct utimbuf __user *times) { process_syscall(204); jprobe_return(); return 0; }
static long jsys_utimes(char __user *filename,
				struct timeval __user *utimes) { process_syscall(205); jprobe_return(); return 0; }
static long jsys_lseek(unsigned int fd, off_t offset,
			  unsigned int whence) { process_syscall(206); jprobe_return(); return 0; }
static long jsys_llseek(unsigned int fd, unsigned long offset_high,
			unsigned long offset_low, loff_t __user *result,
			unsigned int whence) { process_syscall(207); jprobe_return(); return 0; }
static long jsys_read(unsigned int fd, char __user *buf, size_t count) { process_syscall(208); jprobe_return(); return 0; }
static long jsys_readahead(int fd, loff_t offset, size_t count) { process_syscall(209); jprobe_return(); return 0; }
static long jsys_readv(unsigned long fd,
			  const struct iovec __user *vec,
			  unsigned long vlen) { process_syscall(210); jprobe_return(); return 0; }
static long jsys_write(unsigned int fd, const char __user *buf,
			  size_t count) { process_syscall(211); jprobe_return(); return 0; }
static long jsys_writev(unsigned long fd,
			   const struct iovec __user *vec,
			   unsigned long vlen) { process_syscall(212); jprobe_return(); return 0; }
static long jsys_pread64(unsigned int fd, char __user *buf,
			    size_t count, loff_t pos) { process_syscall(213); jprobe_return(); return 0; }
static long jsys_pwrite64(unsigned int fd, const char __user *buf,
			     size_t count, loff_t pos) { process_syscall(214); jprobe_return(); return 0; }
static long jsys_preadv(unsigned long fd, const struct iovec __user *vec,
			   unsigned long vlen, unsigned long pos_l, unsigned long pos_h) { process_syscall(215); jprobe_return(); return 0; }
static long jsys_preadv2(unsigned long fd, const struct iovec __user *vec,
			    unsigned long vlen, unsigned long pos_l, unsigned long pos_h,
			    int flags) { process_syscall(216); jprobe_return(); return 0; }
static long jsys_pwritev(unsigned long fd, const struct iovec __user *vec,
			    unsigned long vlen, unsigned long pos_l, unsigned long pos_h) { process_syscall(217); jprobe_return(); return 0; }
static long jsys_pwritev2(unsigned long fd, const struct iovec __user *vec,
			    unsigned long vlen, unsigned long pos_l, unsigned long pos_h,
			    int flags) { process_syscall(218); jprobe_return(); return 0; }
static long jsys_getcwd(char __user *buf, unsigned long size) { process_syscall(219); jprobe_return(); return 0; }
static long jsys_mkdir(const char __user *pathname, umode_t mode) { process_syscall(220); jprobe_return(); return 0; }
static long jsys_chdir(const char __user *filename) { process_syscall(221); jprobe_return(); return 0; }
static long jsys_fchdir(unsigned int fd) { process_syscall(222); jprobe_return(); return 0; }
static long jsys_rmdir(const char __user *pathname) { process_syscall(223); jprobe_return(); return 0; }
static long jsys_lookup_dcookie(u64 cookie64, char __user *buf, size_t len) { process_syscall(224); jprobe_return(); return 0; }
static long jsys_quotactl(unsigned int cmd, const char __user *special,
				qid_t id, void __user *addr) { process_syscall(225); jprobe_return(); return 0; }
static long jsys_getdents(unsigned int fd,
				struct linux_dirent __user *dirent,
				unsigned int count) { process_syscall(226); jprobe_return(); return 0; }
static long jsys_getdents64(unsigned int fd,
				struct linux_dirent64 __user *dirent,
				unsigned int count) { process_syscall(227); jprobe_return(); return 0; }

static long jsys_setsockopt(int fd, int level, int optname,
				char __user *optval, int optlen) { process_syscall(228); jprobe_return(); return 0; }
static long jsys_getsockopt(int fd, int level, int optname,
				char __user *optval, int __user *optlen) { process_syscall(229); jprobe_return(); return 0; }
static long jsys_bind(int sockfd, struct sockaddr __user *my_addr, int addrlen) { process_syscall(230); jprobe_return(); return 0; }
static long jsys_connect(int sockfd, struct sockaddr __user *addr, int addrlen) { process_syscall(231); jprobe_return(); return 0; }
static long jsys_accept(int sockfd, struct sockaddr __user *addr, int __user *addrlen) { process_syscall(232); jprobe_return(); return 0; }
static long jsys_accept4(int sockfd, struct sockaddr __user *addr, int __user *addrlen, int flags) { process_syscall(233); jprobe_return(); return 0; }
static long jsys_getsockname(int sockfd, struct sockaddr __user *addr, int __user *addrlen) { process_syscall(234); jprobe_return(); return 0; }
static long jsys_getpeername(int sockfd, struct sockaddr __user *addr, int __user *addrlen) { process_syscall(235); jprobe_return(); return 0; }
static long jsys_send(int sockfd, void __user *buf, size_t len, unsigned flags) { process_syscall(236); jprobe_return(); return 0; }
//static long jsys_sendto(int sockfd, void __user *buf, size_t len, unsigned flags,
//				struct sockaddr __user *dest_addr, int addrlen);
long sys_sendmsg(int fd, struct user_msghdr __user *msg, unsigned flags) { process_syscall(237); jprobe_return(); return 0; }
static long jsys_sendmsg(int fd, struct user_msghdr __user *msg, unsigned flags) { process_syscall(238); jprobe_return(); return 0; }
static long jsys_sendmmsg(int fd, struct mmsghdr __user *msg,
			     unsigned int vlen, unsigned flags) { process_syscall(239); jprobe_return(); return 0; }
static long jsys_recv(int sockfd, void __user *buf, size_t len, unsigned flags) { process_syscall(240); jprobe_return(); return 0; }
static long jsys_recvfrom(int sockfd, void __user *buf, size_t len, unsigned flags,
				struct sockaddr __user *src_addr, int __user *addrlen) { process_syscall(241); jprobe_return(); return 0; }
static long jsys_recvmsg(int fd, struct user_msghdr __user *msg, unsigned flags) { process_syscall(242); jprobe_return(); return 0; }
static long jsys_recvmmsg(int fd, struct mmsghdr __user *msg,
			     unsigned int vlen, unsigned flags,
			     struct timespec __user *timeout) { process_syscall(243); jprobe_return(); return 0; }
static long jsys_socket(int domain, int type, int protocol) { process_syscall(244); jprobe_return(); return 0; }
static long jsys_socketpair(int domain, int type, int protocol, int __user *sv) { process_syscall(245); jprobe_return(); return 0; }
static long jsys_socketcall(int call, unsigned long __user *args) { process_syscall(246); jprobe_return(); return 0; }
static long jsys_listen(int sockfd, int backlog) { process_syscall(247); jprobe_return(); return 0; }
static long jsys_poll(struct pollfd __user *ufds, unsigned int nfds,
				int timeout) { process_syscall(248); jprobe_return(); return 0; }
static long jsys_select(int n, fd_set __user *inp, fd_set __user *outp,
			fd_set __user *exp, struct timeval __user *tvp) { process_syscall(249); jprobe_return(); return 0; }
static long jsys_old_select(struct sel_arg_struct __user *arg) { process_syscall(250); jprobe_return(); return 0; }
static long jsys_epoll_create(int size) { process_syscall(251); jprobe_return(); return 0; }
static long jsys_epoll_create1(int flags) { process_syscall(252); jprobe_return(); return 0; }
static long jsys_epoll_ctl(int epfd, int op, int fd,
				struct epoll_event __user *event) { process_syscall(253); jprobe_return(); return 0; }
static long jsys_epoll_wait(int epfd, struct epoll_event __user *events,
				int maxevents, int timeout) { process_syscall(254); jprobe_return(); return 0; }
static long jsys_epoll_pwait(int epfd, struct epoll_event __user *events,
				int maxevents, int timeout,
				const sigset_t __user *sigmask,
				size_t sigsetsize) { process_syscall(255); jprobe_return(); return 0; }
static long jsys_gethostname(char __user *name, int len) { process_syscall(256); jprobe_return(); return 0; }
static long jsys_sethostname(char __user *name, int len) { process_syscall(257); jprobe_return(); return 0; }
static long jsys_setdomainname(char __user *name, int len) { process_syscall(258); jprobe_return(); return 0; }
static long jsys_newuname(struct new_utsname __user *name) { process_syscall(259); jprobe_return(); return 0; }
static long jsys_uname(struct old_utsname __user *buf) { process_syscall(260); jprobe_return(); return 0; }
static long jsys_olduname(struct oldold_utsname __user *buf) { process_syscall(261); jprobe_return(); return 0; }

static long jsys_getrlimit(unsigned int resource,
				struct rlimit __user *rlim) { process_syscall(262); jprobe_return(); return 0; }
#if defined(COMPAT_RLIM_OLD_INFINITY) || !(defined(CONFIG_IA64))
static long jsys_old_getrlimit(unsigned int resource, struct rlimit __user *rlim) { process_syscall(263); jprobe_return(); return 0; }
#endif
static long jsys_setrlimit(unsigned int resource,
				struct rlimit __user *rlim) { process_syscall(264); jprobe_return(); return 0; }
static long jsys_prlimit64(pid_t pid, unsigned int resource,
				const struct rlimit64 __user *new_rlim,
				struct rlimit64 __user *old_rlim) { process_syscall(265); jprobe_return(); return 0; }
static long jsys_getrusage(int who, struct rusage __user *ru) { process_syscall(266); jprobe_return(); return 0; }
static long jsys_umask(int mask) { process_syscall(267); jprobe_return(); return 0; }

static long jsys_msgget(key_t key, int msgflg) { process_syscall(268); jprobe_return(); return 0; }
static long jsys_msgsnd(int msqid, struct msgbuf __user *msgp,
				size_t msgsz, int msgflg) { process_syscall(269); jprobe_return(); return 0; }
static long jsys_msgrcv(int msqid, struct msgbuf __user *msgp,
				size_t msgsz, long msgtyp, int msgflg) { process_syscall(270); jprobe_return(); return 0; }
static long jsys_msgctl(int msqid, int cmd, struct msqid_ds __user *buf) { process_syscall(271); jprobe_return(); return 0; }

static long jsys_semget(key_t key, int nsems, int semflg) { process_syscall(272); jprobe_return(); return 0; }
static long jsys_semop(int semid, struct sembuf __user *sops,
				unsigned nsops) { process_syscall(273); jprobe_return(); return 0; }
static long jsys_semctl(int semid, int semnum, int cmd, unsigned long arg) { process_syscall(274); jprobe_return(); return 0; }
static long jsys_semtimedop(int semid, struct sembuf __user *sops,
				unsigned nsops,
				const struct timespec __user *timeout) { process_syscall(275); jprobe_return(); return 0; }
static long jsys_shmat(int shmid, char __user *shmaddr, int shmflg) { process_syscall(276); jprobe_return(); return 0; }
static long jsys_shmget(key_t key, size_t size, int flag) { process_syscall(277); jprobe_return(); return 0; }
static long jsys_shmdt(char __user *shmaddr) { process_syscall(278); jprobe_return(); return 0; }
static long jsys_shmctl(int shmid, int cmd, struct shmid_ds __user *buf) { process_syscall(279); jprobe_return(); return 0; }
static long jsys_ipc(unsigned int call, int first, unsigned long second,
		unsigned long third, void __user *ptr, long fifth) { process_syscall(280); jprobe_return(); return 0; }

static long jsys_mq_open(const char __user *name, int oflag, umode_t mode, struct mq_attr __user *attr) { process_syscall(281); jprobe_return(); return 0; }
static long jsys_mq_unlink(const char __user *name) { process_syscall(282); jprobe_return(); return 0; }
static long jsys_mq_timedsend(mqd_t mqdes, const char __user *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct timespec __user *abs_timeout) { process_syscall(283); jprobe_return(); return 0; }
static long jsys_mq_timedreceive(mqd_t mqdes, char __user *msg_ptr, size_t msg_len, unsigned int __user *msg_prio, const struct timespec __user *abs_timeout) { process_syscall(284); jprobe_return(); return 0; }
static long jsys_mq_notify(mqd_t mqdes, const struct sigevent __user *notification) { process_syscall(285); jprobe_return(); return 0; }
static long jsys_mq_getsetattr(mqd_t mqdes, const struct mq_attr __user *mqstat, struct mq_attr __user *omqstat) { process_syscall(286); jprobe_return(); return 0; }

static long jsys_pciconfig_iobase(long which, unsigned long bus, unsigned long devfn) { process_syscall(287); jprobe_return(); return 0; }
static long jsys_pciconfig_read(unsigned long bus, unsigned long dfn,
				unsigned long off, unsigned long len,
				void __user *buf) { process_syscall(288); jprobe_return(); return 0; }
static long jsys_pciconfig_write(unsigned long bus, unsigned long dfn,
				unsigned long off, unsigned long len,
				void __user *buf) { process_syscall(289); jprobe_return(); return 0; }

static long jsys_prctl(int option, unsigned long arg2, unsigned long arg3,
			unsigned long arg4, unsigned long arg5) { process_syscall(290); jprobe_return(); return 0; }
static long jsys_swapon(const char __user *specialfile, int swap_flags) { process_syscall(291); jprobe_return(); return 0; }
static long jsys_swapoff(const char __user *specialfile) { process_syscall(292); jprobe_return(); return 0; }
static long jsys_sysctl(struct __sysctl_args __user *args) { process_syscall(293); jprobe_return(); return 0; }
static long jsys_sysinfo(struct sysinfo __user *info) { process_syscall(294); jprobe_return(); return 0; }
static long jsys_sysfs(int option,
				unsigned long arg1, unsigned long arg2) { process_syscall(295); jprobe_return(); return 0; }
static long jsys_syslog(int type, char __user *buf, int len) { process_syscall(296); jprobe_return(); return 0; }
static long jsys_uselib(const char __user *library) { process_syscall(297); jprobe_return(); return 0; }
static long jsys_ni_syscall(void) { process_syscall(298); jprobe_return(); return 0; }
static long jsys_ptrace(long request, long pid, unsigned long addr,
			   unsigned long data) { process_syscall(299); jprobe_return(); return 0; }

static long jsys_add_key(const char __user *_type,
			    const char __user *_description,
			    const void __user *_payload,
			    size_t plen,
			    key_serial_t destringid) { process_syscall(300); jprobe_return(); return 0; }

static long jsys_request_key(const char __user *_type,
				const char __user *_description,
				const char __user *_callout_info,
				key_serial_t destringid) { process_syscall(301); jprobe_return(); return 0; }

static long jsys_keyctl(int cmd, unsigned long arg2, unsigned long arg3,
			   unsigned long arg4, unsigned long arg5) { process_syscall(302); jprobe_return(); return 0; }

static long jsys_ioprio_set(int which, int who, int ioprio) { process_syscall(303); jprobe_return(); return 0; }
static long jsys_ioprio_get(int which, int who) { process_syscall(304); jprobe_return(); return 0; }
static long jsys_set_mempolicy(int mode, const unsigned long __user *nmask,
				unsigned long maxnode) { process_syscall(305); jprobe_return(); return 0; }
static long jsys_migrate_pages(pid_t pid, unsigned long maxnode,
				const unsigned long __user *from,
				const unsigned long __user *to) { process_syscall(306); jprobe_return(); return 0; }
static long jsys_move_pages(pid_t pid, unsigned long nr_pages,
				const void __user * __user *pages,
				const int __user *nodes,
				int __user *status,
				int flags) { process_syscall(307); jprobe_return(); return 0; }
static long jsys_mbind(unsigned long start, unsigned long len,
				unsigned long mode,
				const unsigned long __user *nmask,
				unsigned long maxnode,
				unsigned flags) { process_syscall(308); jprobe_return(); return 0; }
static long jsys_get_mempolicy(int __user *policy,
				unsigned long __user *nmask,
				unsigned long maxnode,
				unsigned long addr, unsigned long flags) { process_syscall(309); jprobe_return(); return 0; }

static long jsys_inotify_init(void) { process_syscall(310); jprobe_return(); return 0; }
static long jsys_inotify_init1(int flags) { process_syscall(311); jprobe_return(); return 0; }
static long jsys_inotify_add_watch(int fd, const char __user *path,
					u32 mask) { process_syscall(312); jprobe_return(); return 0; }
static long jsys_inotify_rm_watch(int fd, __s32 wd) { process_syscall(313); jprobe_return(); return 0; }

static long jsys_spu_run(int fd, __u32 __user *unpc,
				 __u32 __user *ustatus) { process_syscall(314); jprobe_return(); return 0; }
static long jsys_spu_create(const char __user *name,
		unsigned int flags, umode_t mode, int fd) { process_syscall(315); jprobe_return(); return 0; }

static long jsys_mknodat(int dfd, const char __user * filename, umode_t mode,
			    unsigned dev) { process_syscall(316); jprobe_return(); return 0; }
static long jsys_mkdirat(int dfd, const char __user * pathname, umode_t mode) { process_syscall(317); jprobe_return(); return 0; }
static long jsys_unlinkat(int dfd, const char __user * pathname, int flag) { process_syscall(318); jprobe_return(); return 0; }
static long jsys_symlinkat(const char __user * oldname,
			      int newdfd, const char __user * newname) { process_syscall(319); jprobe_return(); return 0; }
static long jsys_linkat(int olddfd, const char __user *oldname,
			   int newdfd, const char __user *newname, int flags) { process_syscall(320); jprobe_return(); return 0; }
static long jsys_renameat(int olddfd, const char __user * oldname,
			     int newdfd, const char __user * newname) { process_syscall(321); jprobe_return(); return 0; }
static long jsys_renameat2(int olddfd, const char __user *oldname,
			      int newdfd, const char __user *newname,
			      unsigned int flags) { process_syscall(322); jprobe_return(); return 0; }
static long jsys_futimesat(int dfd, const char __user *filename,
			      struct timeval __user *utimes) { process_syscall(323); jprobe_return(); return 0; }
static long jsys_faccessat(int dfd, const char __user *filename, int mode) { process_syscall(324); jprobe_return(); return 0; }
static long jsys_fchmodat(int dfd, const char __user * filename,
			     umode_t mode) { process_syscall(325); jprobe_return(); return 0; }
static long jsys_fchownat(int dfd, const char __user *filename, uid_t user,
			     gid_t group, int flag) { process_syscall(326); jprobe_return(); return 0; }
static long jsys_openat(int dfd, const char __user *filename, int flags,
			   umode_t mode) { process_syscall(327); jprobe_return(); return 0; }
static long jsys_newfstatat(int dfd, const char __user *filename,
			       struct stat __user *statbuf, int flag) { process_syscall(328); jprobe_return(); return 0; }
static long jsys_readlinkat(int dfd, const char __user *path, char __user *buf,
			       int bufsiz) { process_syscall(329); jprobe_return(); return 0; }
static long jsys_utimensat(int dfd, const char __user *filename,
				struct timespec __user *utimes, int flags) { process_syscall(330); jprobe_return(); return 0; }
static long jsys_unshare(unsigned long unshare_flags) { process_syscall(331); jprobe_return(); return 0; }

static long jsys_splice(int fd_in, loff_t __user *off_in,
			   int fd_out, loff_t __user *off_out,
			   size_t len, unsigned int flags) { process_syscall(332); jprobe_return(); return 0; }

static long jsys_vmsplice(int fd, const struct iovec __user *iov,
			     unsigned long nr_segs, unsigned int flags) { process_syscall(333); jprobe_return(); return 0; }

static long jsys_tee(int fdin, int fdout, size_t len, unsigned int flags) { process_syscall(334); jprobe_return(); return 0; }

static long jsys_sync_file_range(int fd, loff_t offset, loff_t nbytes,
					unsigned int flags) { process_syscall(335); jprobe_return(); return 0; }
static long jsys_sync_file_range2(int fd, unsigned int flags,
				     loff_t offset, loff_t nbytes) { process_syscall(336); jprobe_return(); return 0; }
static long jsys_get_robust_list(int pid,
				    struct robust_list_head __user * __user *head_ptr,
				    size_t __user *len_ptr) { process_syscall(337); jprobe_return(); return 0; }
static long jsys_set_robust_list(struct robust_list_head __user *head,
				    size_t len) { process_syscall(338); jprobe_return(); return 0; }
static long jsys_getcpu(unsigned __user *cpu, unsigned __user *node, struct getcpu_cache __user *cache) { process_syscall(339); jprobe_return(); return 0; }
static long jsys_signalfd(int ufd, sigset_t __user *user_mask, size_t sizemask) { process_syscall(340); jprobe_return(); return 0; }
static long jsys_signalfd4(int ufd, sigset_t __user *user_mask, size_t sizemask, int flags) { process_syscall(341); jprobe_return(); return 0; }
static long jsys_timerfd_create(int clockid, int flags) { process_syscall(342); jprobe_return(); return 0; }
static long jsys_timerfd_settime(int ufd, int flags,
				    const struct itimerspec __user *utmr,
				    struct itimerspec __user *otmr) { process_syscall(343); jprobe_return(); return 0; }
static long jsys_timerfd_gettime(int ufd, struct itimerspec __user *otmr) { process_syscall(344); jprobe_return(); return 0; }
static long jsys_eventfd(unsigned int count) { process_syscall(345); jprobe_return(); return 0; }
static long jsys_eventfd2(unsigned int count, int flags) { process_syscall(346); jprobe_return(); return 0; }
static long jsys_memfd_create(const char __user *uname_ptr, unsigned int flags) { process_syscall(347); jprobe_return(); return 0; }
static long jsys_userfaultfd(int flags) { process_syscall(348); jprobe_return(); return 0; }
static long jsys_fallocate(int fd, int mode, loff_t offset, loff_t len) { process_syscall(349); jprobe_return(); return 0; }
static long jsys_old_readdir(unsigned int fd, struct old_linux_dirent __user *dirp, unsigned int count) { process_syscall(350); jprobe_return(); return 0; }
static long jsys_pselect6(int i, fd_set __user *fd_set1, fd_set __user *fd_set2,
			     fd_set __user *fd_set3, struct timespec __user *timespec,
			     void __user *v) { process_syscall(351); jprobe_return(); return 0; }
static long jsys_ppoll(struct pollfd __user *fds, unsigned int nfds,
				  struct timespec __user *tmo_p, const sigset_t __user *sigmask,
				  size_t size) { process_syscall(352); jprobe_return(); return 0; }
static long jsys_fanotify_init(unsigned int flags, unsigned int event_f_flags) { process_syscall(353); jprobe_return(); return 0; }
static long jsys_fanotify_mark(int fanotify_fd, unsigned int flags,
				  u64 mask, int fd,
				  const char  __user *pathname) { process_syscall(354); jprobe_return(); return 0; }
static long jsys_syncfs(int fd) { process_syscall(355); jprobe_return(); return 0; }

static long jsys_fork(void) { process_syscall(356); jprobe_return(); return 0; }
static long jsys_vfork(void) { process_syscall(357); jprobe_return(); return 0; }
#ifdef CONFIG_CLONE_BACKWARDS
static long jsys_clone(unsigned long ul1, unsigned long ul2, int __user *i1, unsigned long ul3,
	       int __user *i2) { process_syscall(358); jprobe_return(); return 0; }
#else
#ifdef CONFIG_CLONE_BACKWARDS3
static long jsys_clone(unsigned long ul1, unsigned long ul2, int i1, int __user *i2,
			  int __user *i3, unsigned long ul3) { process_syscall(359); jprobe_return(); return 0; }
#else
static long jsys_clone(unsigned long ul1, unsigned long ul2, int __user *i1,
	       int __user *i2, unsigned long ul3) { process_syscall(360); jprobe_return(); return 0; }
#endif
#endif
/*
static long jsys_execve(const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp) { process_syscall(361); jprobe_return(); return 0; }
*/

static long jsys_perf_event_open(
		struct perf_event_attr __user *attr_uptr,
		pid_t pid, int cpu, int group_fd, unsigned long flags) { process_syscall(362); jprobe_return(); return 0; }

static long jsys_mmap_pgoff(unsigned long addr, unsigned long len,
			unsigned long prot, unsigned long flags,
			unsigned long fd, unsigned long pgoff) { process_syscall(363); jprobe_return(); return 0; }
static long jsys_old_mmap(struct mmap_arg_struct __user *arg) { process_syscall(364); jprobe_return(); return 0; }
static long jsys_name_to_handle_at(int dfd, const char __user *name,
				      struct file_handle __user *handle,
				      int __user *mnt_id, int flag) { process_syscall(365); jprobe_return(); return 0; }
static long jsys_open_by_handle_at(int mountdirfd,
				      struct file_handle __user *handle,
				      int flags) { process_syscall(366); jprobe_return(); return 0; }
static long jsys_setns(int fd, int nstype) { process_syscall(367); jprobe_return(); return 0; }
static long jsys_process_vm_readv(pid_t pid,
				     const struct iovec __user *lvec,
				     unsigned long liovcnt,
				     const struct iovec __user *rvec,
				     unsigned long riovcnt,
				     unsigned long flags) { process_syscall(368); jprobe_return(); return 0; }
static long jsys_process_vm_writev(pid_t pid,
				      const struct iovec __user *lvec,
				      unsigned long liovcnt,
				      const struct iovec __user *rvec,
				      unsigned long riovcnt,
				      unsigned long flags) { process_syscall(369); jprobe_return(); return 0; }

static long jsys_kcmp(pid_t pid1, pid_t pid2, int type,
			 unsigned long idx1, unsigned long idx2) { process_syscall(370); jprobe_return(); return 0; }
static long jsys_finit_module(int fd, const char __user *uargs, int flags) { process_syscall(371); jprobe_return(); return 0; }
static long jsys_seccomp(unsigned int op, unsigned int flags,
			    const char __user *uargs) { process_syscall(372); jprobe_return(); return 0; }
static long jsys_getrandom(char __user *buf, size_t count,
			      unsigned int flags) { process_syscall(373); jprobe_return(); return 0; }
static long jsys_bpf(int cmd, union bpf_attr *attr, unsigned int size) { process_syscall(374); jprobe_return(); return 0; }

static long jsys_execveat(int dfd, const char __user *filename,
			const char __user *const __user *argv,
			const char __user *const __user *envp, int flags) { process_syscall(375); jprobe_return(); return 0; }

static long jsys_membarrier(int cmd, int flags) { process_syscall(376); jprobe_return(); return 0; }
static long jsys_copy_file_range(int fd_in, loff_t __user *off_in,
				    int fd_out, loff_t __user *off_out,
				    size_t len, unsigned int flags) { process_syscall(377); jprobe_return(); return 0; }

static long jsys_mlock2(unsigned long start, size_t len, int flags) { process_syscall(378); jprobe_return(); return 0; }

static long jsys_pkey_mprotect(unsigned long start, size_t len,
				  unsigned long prot, int pkey) { process_syscall(379); jprobe_return(); return 0; }
static long jsys_pkey_alloc(unsigned long flags, unsigned long init_val) { process_syscall(380); jprobe_return(); return 0; }
static long jsys_pkey_free(int pkey) { process_syscall(381); jprobe_return(); return 0; }
static long jsys_statx(int dfd, const char __user *path, unsigned flags, unsigned mask, struct statx __user *buffer) { process_syscall(382); jprobe_return(); return 0; }
// jsys_sigreturn has signum 383

// JProbe handlers
struct jprobe jprobes_array[] = {
	
	{
		.entry = jsys32_quotactl,
		.kp = {
			.symbol_name = "sys32_quotactl",
		},
	},

	{
		.entry = jsys_time,
		.kp = {
			.symbol_name = "sys_time",
		},
	},

	{
		.entry = jsys_stime,
		.kp = {
			.symbol_name = "sys_stime",
		},
	},
	
	
	{
		.entry = jsys_gettimeofday,
		.kp = {
			.symbol_name = "sys_gettimeofday",
		},
	},
	
	
	{
		.entry = jsys_settimeofday,
		.kp = {
			.symbol_name = "sys_settimeofday",
		},
	},
	
	
	{
		.entry = jsys_adjtimex,
		.kp = {
			.symbol_name = "sys_adjtimex",
		},
	},

	{
		.entry = jsys_times,
		.kp = {
			.symbol_name = "sys_times",
		},
	},

	{
		.entry = jsys_gettid,
		.kp = {
			.symbol_name = "sys_gettid",
		},
	},

	{
		.entry = jsys_nanosleep,
		.kp = {
			.symbol_name = "sys_nanosleep",
		},
	},

	{
		.entry = jsys_alarm,
		.kp = {
			.symbol_name = "sys_alarm",
		},
	},

	{
		.entry = jsys_getpid,
		.kp = {
			.symbol_name = "sys_getpid",
		},
	},

	{
		.entry = jsys_getppid,
		.kp = {
			.symbol_name = "sys_getppid",
		},
	},

	{
		.entry = jsys_getuid,
		.kp = {
			.symbol_name = "sys_getuid",
		},
	},

	{
		.entry = jsys_geteuid,
		.kp = {
			.symbol_name = "sys_geteuid",
		},
	},

	{
		.entry = jsys_getgid,
		.kp = {
			.symbol_name = "sys_getgid",
		},
	},

	{
		.entry = jsys_getegid,
		.kp = {
			.symbol_name = "sys_getegid",
		},
	},

	{
		.entry = jsys_getresuid,
		.kp = {
			.symbol_name = "sys_getresuid",
		},
	},

	{
		.entry = jsys_getresgid,
		.kp = {
			.symbol_name = "sys_getresgid",
		},
	},

	{
		.entry = jsys_getpgid,
		.kp = {
			.symbol_name = "sys_getpgid",
		},
	},

	{
		.entry = jsys_getpgrp,
		.kp = {
			.symbol_name = "sys_getpgrp",
		},
	},

	{
		.entry = jsys_getsid,
		.kp = {
			.symbol_name = "sys_getsid",
		},
	},

	{
		.entry = jsys_getgroups,
		.kp = {
			.symbol_name = "sys_getgroups",
		},
	},

	{
		.entry = jsys_setregid,
		.kp = {
			.symbol_name = "sys_setregid",
		},
	},

	{
		.entry = jsys_setgid,
		.kp = {
			.symbol_name = "sys_setgid",
		},
	},

	{
		.entry = jsys_setreuid,
		.kp = {
			.symbol_name = "sys_setreuid",
		},
	},

	{
		.entry = jsys_setuid,
		.kp = {
			.symbol_name = "sys_setuid",
		},
	},

	{
		.entry = jsys_setresuid,
		.kp = {
			.symbol_name = "sys_setresuid",
		},
	},

	{
		.entry = jsys_setresgid,
		.kp = {
			.symbol_name = "sys_setresgid",
		},
	},

	{
		.entry = jsys_setfsuid,
		.kp = {
			.symbol_name = "sys_setfsuid",
		},
	},

	{
		.entry = jsys_setfsgid,
		.kp = {
			.symbol_name = "sys_setfsgid",
		},
	},

	{
		.entry = jsys_setpgid,
		.kp = {
			.symbol_name = "sys_setpgid",
		},
	},

	{
		.entry = jsys_setsid,
		.kp = {
			.symbol_name = "sys_setsid",
		},
	},

	{
		.entry = jsys_setgroups,
		.kp = {
			.symbol_name = "sys_setgroups",
		},
	},

	{
		.entry = jsys_acct,
		.kp = {
			.symbol_name = "sys_acct",
		},
	},

	{
		.entry = jsys_capget,
		.kp = {
			.symbol_name = "sys_capget",
		},
	},

	{
		.entry = jsys_capset,
		.kp = {
			.symbol_name = "sys_capset",
		},
	},

	{
		.entry = jsys_personality,
		.kp = {
			.symbol_name = "sys_personality",
		},
	},

	{
		.entry = jsys_sigpending,
		.kp = {
			.symbol_name = "sys_sigpending",
		},
	},

	{
		.entry = jsys_sigprocmask,
		.kp = {
			.symbol_name = "sys_sigprocmask",
		},
	},

	{
		.entry = jsys_sigaltstack,
		.kp = {
			.symbol_name = "sys_sigaltstack",
		},
	},

	{
		.entry = jsys_getitimer,
		.kp = {
			.symbol_name = "sys_getitimer",
		},
	},

	{
		.entry = jsys_setitimer,
		.kp = {
			.symbol_name = "sys_setitimer",
		},
	},
	

	{
		.entry = jsys_timer_create,
		.kp = {
			.symbol_name = "sys_timer_create",
		},
	},
	
	
	{
		.entry = jsys_timer_gettime,
		.kp = {
			.symbol_name = "sys_timer_gettime",
		},
	},

	{
		.entry = jsys_timer_getoverrun,
		.kp = {
			.symbol_name = "sys_timer_getoverrun",
		},
	},

	{
		.entry = jsys_timer_settime,
		.kp = {
			.symbol_name = "sys_timer_settime",
		},
	},

	{
		.entry = jsys_timer_delete,
		.kp = {
			.symbol_name = "sys_timer_delete",
		},
	},

	{
		.entry = jsys_clock_settime,
		.kp = {
			.symbol_name = "sys_clock_settime",
		},
	},

	{
		.entry = jsys_clock_gettime,
		.kp = {
			.symbol_name = "sys_clock_gettime",
		},
	},

	{
		.entry = jsys_clock_adjtime,
		.kp = {
			.symbol_name = "sys_clock_adjtime",
		},
	},

	{
		.entry = jsys_clock_getres,
		.kp = {
			.symbol_name = "sys_clock_getres",
		},
	},

	{
		.entry = jsys_clock_nanosleep,
		.kp = {
			.symbol_name = "sys_clock_nanosleep",
		},
	},
	
	
	{
		.entry = jsys_nice,
		.kp = {
			.symbol_name = "sys_nice",
		},
	},

	{
		.entry = jsys_sched_setscheduler,
		.kp = {
			.symbol_name = "sys_sched_setscheduler",
		},
	},

	{
		.entry = jsys_sched_setparam,
		.kp = {
			.symbol_name = "sys_sched_setparam",
		},
	},

	{
		.entry = jsys_sched_setattr,
		.kp = {
			.symbol_name = "sys_sched_setattr",
		},
	},

	{
		.entry = jsys_sched_getscheduler,
		.kp = {
			.symbol_name = "sys_sched_getscheduler",
		},
	},

	{
		.entry = jsys_sched_getparam,
		.kp = {
			.symbol_name = "sys_sched_getparam",
		},
	},

	{
		.entry = jsys_sched_getattr,
		.kp = {
			.symbol_name = "sys_sched_getattr",
		},
	},

	{
		.entry = jsys_sched_setaffinity,
		.kp = {
			.symbol_name = "sys_sched_setaffinity",
		},
	},

	{
		.entry = jsys_sched_getaffinity,
		.kp = {
			.symbol_name = "sys_sched_getaffinity",
		},
	},

	{
		.entry = jsys_sched_yield,
		.kp = {
			.symbol_name = "sys_sched_yield",
		},
	},

	{
		.entry = jsys_sched_get_priority_max,
		.kp = {
			.symbol_name = "sys_sched_get_priority_max",
		},
	},

	{
		.entry = jsys_sched_get_priority_min,
		.kp = {
			.symbol_name = "sys_sched_get_priority_min",
		},
	},

	{
		.entry = jsys_sched_rr_get_interval,
		.kp = {
			.symbol_name = "sys_sched_rr_get_interval",
		},
	},

	{
		.entry = jsys_setpriority,
		.kp = {
			.symbol_name = "sys_setpriority",
		},
	},

	{
		.entry = jsys_getpriority,
		.kp = {
			.symbol_name = "sys_getpriority",
		},
	},

	{
		.entry = jsys_shutdown,
		.kp = {
			.symbol_name = "sys_shutdown",
		},
	},
	

	{
		.entry = jsys_reboot,
		.kp = {
			.symbol_name = "sys_reboot",
		},
	},
	
	
	{
		.entry = jsys_restart_syscall,
		.kp = {
			.symbol_name = "sys_restart_syscall",
		},
	},

	{
		.entry = jsys_kexec_load,
		.kp = {
			.symbol_name = "sys_kexec_load",
		},
	},

	{
		.entry = jsys_kexec_file_load,
		.kp = {
			.symbol_name = "sys_kexec_file_load",
		},
	},
	
	
	{
		.entry = jsys_exit,
		.kp = {
			.symbol_name = "sys_exit",
		},
	},

	
	{
		.entry = jsys_exit_group,
		.kp = {
			.symbol_name = "sys_exit_group",
		},
	},
	
	{
		.entry = jsys_wait4,
		.kp = {
			.symbol_name = "sys_wait4",
		},
	},

	{
		.entry = jsys_waitid,
		.kp = {
			.symbol_name = "sys_waitid",
		},
	},

	{
		.entry = jsys_waitpid,
		.kp = {
			.symbol_name = "sys_waitpid",
		},
	},

	{
		.entry = jsys_set_tid_address,
		.kp = {
			.symbol_name = "sys_set_tid_address",
		},
	},

	
	{
		.entry = jsys_futex,
		.kp = {
			.symbol_name = "sys_futex",
		},
	},

	
	{
		.entry = jsys_init_module,
		.kp = {
			.symbol_name = "sys_init_module",
		},
	},

	{
		.entry = jsys_delete_module,
		.kp = {
			.symbol_name = "sys_delete_module",
		},
	},
	

	
	{
		.entry = jsys_sigsuspend,
		.kp = {
			.symbol_name = "sys_sigsuspend",
		},
	},
	
	
	
	{
		.entry = jsys_rt_sigsuspend,
		.kp = {
			.symbol_name = "sys_rt_sigsuspend",
		},
	},
	
	
	
#ifdef CONFIG_OLD_SIGACTION
	{
		.entry = jsys_sigaction,
		.kp = {
			.symbol_name = "sys_sigaction",
		},
	},
#endif
	

	
#ifndef CONFIG_ODD_RT_SIGACTION
	{
		.entry = jsys_rt_sigaction,
		.kp = {
			.symbol_name = "sys_rt_sigaction",
		},
	},
#endif
	

	
	{
		.entry = jsys_rt_sigprocmask,
		.kp = {
			.symbol_name = "sys_rt_sigprocmask",
		},
	},

	{
		.entry = jsys_rt_sigpending,
		.kp = {
			.symbol_name = "sys_rt_sigpending",
		},
	},

	{
		.entry = jsys_rt_sigtimedwait,
		.kp = {
			.symbol_name = "sys_rt_sigtimedwait",
		},
	},

	{
		.entry = jsys_rt_tgsigqueueinfo,
		.kp = {
			.symbol_name = "sys_rt_tgsigqueueinfo",
		},
	},

	{
		.entry = jsys_kill,
		.kp = {
			.symbol_name = "sys_kill",
		},
	},

	{
		.entry = jsys_tgkill,
		.kp = {
			.symbol_name = "sys_tgkill",
		},
	},

	{
		.entry = jsys_tkill,
		.kp = {
			.symbol_name = "sys_tkill",
		},
	},

	{
		.entry = jsys_rt_sigqueueinfo,
		.kp = {
			.symbol_name = "sys_rt_sigqueueinfo",
		},
	},

	{
		.entry = jsys_sgetmask,
		.kp = {
			.symbol_name = "sys_sgetmask",
		},
	},

	{
		.entry = jsys_ssetmask,
		.kp = {
			.symbol_name = "sys_ssetmask",
		},
	},

	{
		.entry = jsys_signal,
		.kp = {
			.symbol_name = "sys_signal",
		},
	},

	{
		.entry = jsys_pause,
		.kp = {
			.symbol_name = "sys_pause",
		},
	},

	{
		.entry = jsys_sync,
		.kp = {
			.symbol_name = "sys_sync",
		},
	},

	{
		.entry = jsys_fsync,
		.kp = {
			.symbol_name = "sys_fsync",
		},
	},

	{
		.entry = jsys_fdatasync,
		.kp = {
			.symbol_name = "sys_fdatasync",
		},
	},

	{
		.entry = jsys_bdflush,
		.kp = {
			.symbol_name = "sys_bdflush",
		},
	},

	
	{
		.entry = jsys_mount,
		.kp = {
			.symbol_name = "sys_mount",
		},
	},

	{
		.entry = jsys_umount,
		.kp = {
			.symbol_name = "sys_umount",
		},
	},

	{
		.entry = jsys_oldumount,
		.kp = {
			.symbol_name = "sys_oldumount",
		},
	},

	{
		.entry = jsys_truncate,
		.kp = {
			.symbol_name = "sys_truncate",
		},
	},

	{
		.entry = jsys_ftruncate,
		.kp = {
			.symbol_name = "sys_ftruncate",
		},
	},

	
	{
		.entry = jsys_stat,
		.kp = {
			.symbol_name = "sys_stat",
		},
	},

	{
		.entry = jsys_statfs,
		.kp = {
			.symbol_name = "sys_statfs",
		},
	},

	{
		.entry = jsys_statfs64,
		.kp = {
			.symbol_name = "sys_statfs64",
		},
	},

	{
		.entry = jsys_fstatfs,
		.kp = {
			.symbol_name = "sys_fstatfs",
		},
	},

	{
		.entry = jsys_fstatfs64,
		.kp = {
			.symbol_name = "sys_fstatfs64",
		},
	},

	{
		.entry = jsys_lstat,
		.kp = {
			.symbol_name = "sys_lstat",
		},
	},

	{
		.entry = jsys_fstat,
		.kp = {
			.symbol_name = "sys_fstat",
		},
	},

	{
		.entry = jsys_newstat,
		.kp = {
			.symbol_name = "sys_newstat",
		},
	},

	{
		.entry = jsys_newlstat,
		.kp = {
			.symbol_name = "sys_newlstat",
		},
	},

	{
		.entry = jsys_newfstat,
		.kp = {
			.symbol_name = "sys_newfstat",
		},
	},

	{
		.entry = jsys_ustat,
		.kp = {
			.symbol_name = "sys_ustat",
		},
	},

	
#if defined (__ARCH_WANT_STAT64) || defined (__ARCH_WANT_COMPAT_STAT64)
	{
		.entry = jsys_stat64,
		.kp = {
			.symbol_name = "sys_stat64",
		},
	},

	{
		.entry = jsys_fstat64,
		.kp = {
			.symbol_name = "sys_fstat64",
		},
	},

	{
		.entry = jsys_lstat64,
		.kp = {
			.symbol_name = "sys_lstat64",
		},
	},

	{
		.entry = jsys_fstatat64,
		.kp = {
			.symbol_name = "sys_fstatat64",
		},
	},
#endif
#if BITS_PER_LONG == 32
	{
		.entry = jsys_truncate64,
		.kp = {
			.symbol_name = "sys_truncate64",
		},
	},

	{
		.entry = jsys_ftruncate64,
		.kp = {
			.symbol_name = "sys_ftruncate64",
		},
	},
#endif
	
	
	
	{
		.entry = jsys_setxattr,
		.kp = {
			.symbol_name = "sys_setxattr",
		},
	},

	{
		.entry = jsys_lsetxattr,
		.kp = {
			.symbol_name = "sys_lsetxattr",
		},
	},

	{
		.entry = jsys_fsetxattr,
		.kp = {
			.symbol_name = "sys_fsetxattr",
		},
	},

	{
		.entry = jsys_getxattr,
		.kp = {
			.symbol_name = "sys_getxattr",
		},
	},

	{
		.entry = jsys_lgetxattr,
		.kp = {
			.symbol_name = "sys_lgetxattr",
		},
	},

	{
		.entry = jsys_fgetxattr,
		.kp = {
			.symbol_name = "sys_fgetxattr",
		},
	},

	{
		.entry = jsys_listxattr,
		.kp = {
			.symbol_name = "sys_listxattr",
		},
	},

	{
		.entry = jsys_llistxattr,
		.kp = {
			.symbol_name = "sys_llistxattr",
		},
	},

	{
		.entry = jsys_flistxattr,
		.kp = {
			.symbol_name = "sys_flistxattr",
		},
	},

	{
		.entry = jsys_removexattr,
		.kp = {
			.symbol_name = "sys_removexattr",
		},
	},

	{
		.entry = jsys_lremovexattr,
		.kp = {
			.symbol_name = "sys_lremovexattr",
		},
	},

	{
		.entry = jsys_fremovexattr,
		.kp = {
			.symbol_name = "sys_fremovexattr",
		},
	},

	{
		.entry = jsys_brk,
		.kp = {
			.symbol_name = "sys_brk",
		},
	},

	{
		.entry = jsys_mprotect,
		.kp = {
			.symbol_name = "sys_mprotect",
		},
	},

	{
		.entry = jsys_mremap,
		.kp = {
			.symbol_name = "sys_mremap",
		},
	},

	{
		.entry = jsys_remap_file_pages,
		.kp = {
			.symbol_name = "sys_remap_file_pages",
		},
	},

	{
		.entry = jsys_msync,
		.kp = {
			.symbol_name = "sys_msync",
		},
	},

	{
		.entry = jsys_fadvise64,
		.kp = {
			.symbol_name = "sys_fadvise64",
		},
	},

	{
		.entry = jsys_fadvise64_64,
		.kp = {
			.symbol_name = "sys_fadvise64_64",
		},
	},

	{
		.entry = jsys_munmap,
		.kp = {
			.symbol_name = "sys_munmap",
		},
	},

	{
		.entry = jsys_mlock,
		.kp = {
			.symbol_name = "sys_mlock",
		},
	},

	{
		.entry = jsys_munlock,
		.kp = {
			.symbol_name = "sys_munlock",
		},
	},

	{
		.entry = jsys_mlockall,
		.kp = {
			.symbol_name = "sys_mlockall",
		},
	},

	{
		.entry = jsys_munlockall,
		.kp = {
			.symbol_name = "sys_munlockall",
		},
	},

	{
		.entry = jsys_madvise,
		.kp = {
			.symbol_name = "sys_madvise",
		},
	},

	{
		.entry = jsys_mincore,
		.kp = {
			.symbol_name = "sys_mincore",
		},
	},

	{
		.entry = jsys_pivot_root,
		.kp = {
			.symbol_name = "sys_pivot_root",
		},
	},

	{
		.entry = jsys_chroot,
		.kp = {
			.symbol_name = "sys_chroot",
		},
	},

	{
		.entry = jsys_mknod,
		.kp = {
			.symbol_name = "sys_mknod",
		},
	},
	

	
	{
		.entry = jsys_link,
		.kp = {
			.symbol_name = "sys_link",
		},
	},

	{
		.entry = jsys_symlink,
		.kp = {
			.symbol_name = "sys_symlink",
		},
	},

	{
		.entry = jsys_unlink,
		.kp = {
			.symbol_name = "sys_unlink",
		},
	},

	{
		.entry = jsys_rename,
		.kp = {
			.symbol_name = "sys_rename",
		},
	},

	{
		.entry = jsys_chmod,
		.kp = {
			.symbol_name = "sys_chmod",
		},
	},

	{
		.entry = jsys_fchmod,
		.kp = {
			.symbol_name = "sys_fchmod",
		},
	},

	{
		.entry = jsys_fcntl,
		.kp = {
			.symbol_name = "sys_fcntl",
		},
	},

	
#if BITS_PER_LONG == 32
	{
		.entry = jsys_fcntl64,
		.kp = {
			.symbol_name = "sys_fcntl64",
		},
	},
#endif
	
	
	
	{
		.entry = jsys_pipe,
		.kp = {
			.symbol_name = "sys_pipe",
		},
	},

	{
		.entry = jsys_pipe2,
		.kp = {
			.symbol_name = "sys_pipe2",
		},
	},

	{
		.entry = jsys_dup,
		.kp = {
			.symbol_name = "sys_dup",
		},
	},

	{
		.entry = jsys_dup2,
		.kp = {
			.symbol_name = "sys_dup2",
		},
	},

	{
		.entry = jsys_dup3,
		.kp = {
			.symbol_name = "sys_dup3",
		},
	},

	{
		.entry = jsys_ioperm,
		.kp = {
			.symbol_name = "sys_ioperm",
		},
	},

	{
		.entry = jsys_ioctl,
		.kp = {
			.symbol_name = "sys_ioctl",
		},
	},

	{
		.entry = jsys_flock,
		.kp = {
			.symbol_name = "sys_flock",
		},
	},

	{
		.entry = jsys_io_setup,
		.kp = {
			.symbol_name = "sys_io_setup",
		},
	},

	{
		.entry = jsys_io_destroy,
		.kp = {
			.symbol_name = "sys_io_destroy",
		},
	},

	{
		.entry = jsys_io_getevents,
		.kp = {
			.symbol_name = "sys_io_getevents",
		},
	},

	{
		.entry = jsys_io_submit,
		.kp = {
			.symbol_name = "sys_io_submit",
		},
	},

	{
		.entry = jsys_io_cancel,
		.kp = {
			.symbol_name = "sys_io_cancel",
		},
	},

	{
		.entry = jsys_sendfile,
		.kp = {
			.symbol_name = "sys_sendfile",
		},
	},

	{
		.entry = jsys_sendfile64,
		.kp = {
			.symbol_name = "sys_sendfile64",
		},
	},

	{
		.entry = jsys_readlink,
		.kp = {
			.symbol_name = "sys_readlink",
		},
	},

	{
		.entry = jsys_creat,
		.kp = {
			.symbol_name = "sys_creat",
		},
	},
	
	
	{
		.entry = jsys_open,
		.kp = {
			.symbol_name = "sys_open",
		},
	},

	
	{
		.entry = jsys_close,
		.kp = {
			.symbol_name = "sys_close",
		},
	},

	
	{
		.entry = jsys_access,
		.kp = {
			.symbol_name = "sys_access",
		},
	},

	{
		.entry = jsys_vhangup,
		.kp = {
			.symbol_name = "sys_vhangup",
		},
	},

	{
		.entry = jsys_chown,
		.kp = {
			.symbol_name = "sys_chown",
		},
	},

	{
		.entry = jsys_lchown,
		.kp = {
			.symbol_name = "sys_lchown",
		},
	},

	{
		.entry = jsys_fchown,
		.kp = {
			.symbol_name = "sys_fchown",
		},
	},
	
	
#ifdef CONFIG_HAVE_UID16
	{
		.entry = jsys_chown16,
		.kp = {
			.symbol_name = "sys_chown16",
		},
	},

	{
		.entry = jsys_lchown16,
		.kp = {
			.symbol_name = "sys_lchown16",
		},
	},

	{
		.entry = jsys_fchown16,
		.kp = {
			.symbol_name = "sys_fchown16",
		},
	},

	{
		.entry = jsys_setregid16,
		.kp = {
			.symbol_name = "sys_setregid16",
		},
	},

	{
		.entry = jsys_setgid16,
		.kp = {
			.symbol_name = "sys_setgid16",
		},
	},

	{
		.entry = jsys_setreuid16,
		.kp = {
			.symbol_name = "sys_setreuid16",
		},
	},

	{
		.entry = jsys_setuid16,
		.kp = {
			.symbol_name = "sys_setuid16",
		},
	},

	{
		.entry = jsys_setresuid16,
		.kp = {
			.symbol_name = "sys_setresuid16",
		},
	},

	{
		.entry = jsys_getresuid16,
		.kp = {
			.symbol_name = "sys_getresuid16",
		},
	},

	{
		.entry = jsys_setresgid16,
		.kp = {
			.symbol_name = "sys_setresgid16",
		},
	},

	{
		.entry = jsys_getresgid16,
		.kp = {
			.symbol_name = "sys_getresgid16",
		},
	},

	{
		.entry = jsys_setfsuid16,
		.kp = {
			.symbol_name = "sys_setfsuid16",
		},
	},

	{
		.entry = jsys_setfsgid16,
		.kp = {
			.symbol_name = "sys_setfsgid16",
		},
	},

	{
		.entry = jsys_getgroups16,
		.kp = {
			.symbol_name = "sys_getgroups16",
		},
	},

	{
		.entry = jsys_setgroups16,
		.kp = {
			.symbol_name = "sys_setgroups16",
		},
	},

	{
		.entry = jsys_getuid16,
		.kp = {
			.symbol_name = "sys_getuid16",
		},
	},

	{
		.entry = jsys_geteuid16,
		.kp = {
			.symbol_name = "sys_geteuid16",
		},
	},

	{
		.entry = jsys_getgid16,
		.kp = {
			.symbol_name = "sys_getgid16",
		},
	},

	{
		.entry = jsys_getegid16,
		.kp = {
			.symbol_name = "sys_getegid16",
		},
	},
#endif
	

	
	{
		.entry = jsys_utime,
		.kp = {
			.symbol_name = "sys_utime",
		},
	},

	{
		.entry = jsys_utimes,
		.kp = {
			.symbol_name = "sys_utimes",
		},
	},
	

	{
		.entry = jsys_lseek,
		.kp = {
			.symbol_name = "sys_lseek",
		},
	},

	{
		.entry = jsys_llseek,
		.kp = {
			.symbol_name = "sys_llseek",
		},
	},
	
	
	{
		.entry = jsys_read,
		.kp = {
			.symbol_name = "sys_read",
		},
	},

	
	{
		.entry = jsys_readahead,
		.kp = {
			.symbol_name = "sys_readahead",
		},
	},

	{
		.entry = jsys_readv,
		.kp = {
			.symbol_name = "sys_readv",
		},
	},
	

	
	{
		.entry = jsys_write,
		.kp = {
			.symbol_name = "sys_write",
		},
	},
	
	
	{
		.entry = jsys_writev,
		.kp = {
			.symbol_name = "sys_writev",
		},
	},

	{
		.entry = jsys_pread64,
		.kp = {
			.symbol_name = "sys_pread64",
		},
	},

	{
		.entry = jsys_pwrite64,
		.kp = {
			.symbol_name = "sys_pwrite64",
		},
	},

	{
		.entry = jsys_preadv,
		.kp = {
			.symbol_name = "sys_preadv",
		},
	},

	{
		.entry = jsys_preadv2,
		.kp = {
			.symbol_name = "sys_preadv2",
		},
	},

	{
		.entry = jsys_pwritev,
		.kp = {
			.symbol_name = "sys_pwritev",
		},
	},

	{
		.entry = jsys_pwritev2,
		.kp = {
			.symbol_name = "sys_pwritev2",
		},
	},

	{
		.entry = jsys_getcwd,
		.kp = {
			.symbol_name = "sys_getcwd",
		},
	},
	

	
	{
		.entry = jsys_mkdir,
		.kp = {
			.symbol_name = "sys_mkdir",
		},
	},

	{
		.entry = jsys_chdir,
		.kp = {
			.symbol_name = "sys_chdir",
		},
	},

	{
		.entry = jsys_fchdir,
		.kp = {
			.symbol_name = "sys_fchdir",
		},
	},

	{
		.entry = jsys_rmdir,
		.kp = {
			.symbol_name = "sys_rmdir",
		},
	},

	
	{
		.entry = jsys_lookup_dcookie,
		.kp = {
			.symbol_name = "sys_lookup_dcookie",
		},
	},
	

	{
		.entry = jsys_quotactl,
		.kp = {
			.symbol_name = "sys_quotactl",
		},
	},

	
	{
		.entry = jsys_getdents,
		.kp = {
			.symbol_name = "sys_getdents",
		},
	},

	{
		.entry = jsys_getdents64,
		.kp = {
			.symbol_name = "sys_getdents64",
		},
	},

	{
		.entry = jsys_setsockopt,
		.kp = {
			.symbol_name = "sys_setsockopt",
		},
	},

	{
		.entry = jsys_getsockopt,
		.kp = {
			.symbol_name = "sys_getsockopt",
		},
	},

	{
		.entry = jsys_bind,
		.kp = {
			.symbol_name = "sys_bind",
		},
	},

	{
		.entry = jsys_connect,
		.kp = {
			.symbol_name = "sys_connect",
		},
	},

	{
		.entry = jsys_accept,
		.kp = {
			.symbol_name = "sys_accept",
		},
	},

	{
		.entry = jsys_accept4,
		.kp = {
			.symbol_name = "sys_accept4",
		},
	},

	{
		.entry = jsys_getsockname,
		.kp = {
			.symbol_name = "sys_getsockname",
		},
	},

	{
		.entry = jsys_getpeername,
		.kp = {
			.symbol_name = "sys_getpeername",
		},
	},

	{
		.entry = jsys_send,
		.kp = {
			.symbol_name = "sys_send",
		},
	},

	/* // Somehow this syscall was messed up (see above)
	{
		.entry = jsys_sendto,
		.kp = {
			.symbol_name = "sys_sendto",
		},
	},
	*/

	
	{
		.entry = jsys_sendmsg,
		.kp = {
			.symbol_name = "sys_sendmsg",
		},
	},

	{
		.entry = jsys_sendmmsg,
		.kp = {
			.symbol_name = "sys_sendmmsg",
		},
	},

	{
		.entry = jsys_recv,
		.kp = {
			.symbol_name = "sys_recv",
		},
	},

	{
		.entry = jsys_recvfrom,
		.kp = {
			.symbol_name = "sys_recvfrom",
		},
	},

	{
		.entry = jsys_recvmsg,
		.kp = {
			.symbol_name = "sys_recvmsg",
		},
	},

	{
		.entry = jsys_recvmmsg,
		.kp = {
			.symbol_name = "sys_recvmmsg",
		},
	},

	{
		.entry = jsys_socket,
		.kp = {
			.symbol_name = "sys_socket",
		},
	},

	{
		.entry = jsys_socketpair,
		.kp = {
			.symbol_name = "sys_socketpair",
		},
	},

	{
		.entry = jsys_socketcall,
		.kp = {
			.symbol_name = "sys_socketcall",
		},
	},

	{
		.entry = jsys_listen,
		.kp = {
			.symbol_name = "sys_listen",
		},
	},
	
	{
		.entry = jsys_poll,
		.kp = {
			.symbol_name = "sys_poll",
		},
	},

	
	{
		.entry = jsys_select,
		.kp = {
			.symbol_name = "sys_select",
		},
	},
	

	/* // Anil believes this syscall may not exist
	{
		.entry = jsys_old_select,
		.kp = {
			.symbol_name = "sys_old_select",
		},
	},
	*/
	
	
	{
		.entry = jsys_epoll_create,
		.kp = {
			.symbol_name = "sys_epoll_create",
		},
	},

	{
		.entry = jsys_epoll_create1,
		.kp = {
			.symbol_name = "sys_epoll_create1",
		},
	},

	{
		.entry = jsys_epoll_ctl,
		.kp = {
			.symbol_name = "sys_epoll_ctl",
		},
	},

	{
		.entry = jsys_epoll_wait,
		.kp = {
			.symbol_name = "sys_epoll_wait",
		},
	},

	{
		.entry = jsys_epoll_pwait,
		.kp = {
			.symbol_name = "sys_epoll_pwait",
		},
	},

	{
		.entry = jsys_gethostname,
		.kp = {
			.symbol_name = "sys_gethostname",
		},
	},
	
	
	
	{
		.entry = jsys_sethostname,
		.kp = {
			.symbol_name = "sys_sethostname",
		},
	},

	{
		.entry = jsys_setdomainname,
		.kp = {
			.symbol_name = "sys_setdomainname",
		},
	},

	{
		.entry = jsys_newuname,
		.kp = {
			.symbol_name = "sys_newuname",
		},
	},

	{
		.entry = jsys_uname,
		.kp = {
			.symbol_name = "sys_uname",
		},
	},

	{
		.entry = jsys_olduname,
		.kp = {
			.symbol_name = "sys_olduname",
		},
	},

	{
		.entry = jsys_getrlimit,
		.kp = {
			.symbol_name = "sys_getrlimit",
		},
	},
	

	
#if defined(COMPAT_RLIM_OLD_INFINITY) || !(defined(CONFIG_IA64))
	{
		.entry = jsys_old_getrlimit,
		.kp = {
			.symbol_name = "sys_old_getrlimit",
		},
	},
#endif
	

	
	{
		.entry = jsys_setrlimit,
		.kp = {
			.symbol_name = "sys_setrlimit",
		},
	},

	{
		.entry = jsys_prlimit64,
		.kp = {
			.symbol_name = "sys_prlimit64",
		},
	},

	{
		.entry = jsys_getrusage,
		.kp = {
			.symbol_name = "sys_getrusage",
		},
	},

	{
		.entry = jsys_umask,
		.kp = {
			.symbol_name = "sys_umask",
		},
	},

	{
		.entry = jsys_msgget,
		.kp = {
			.symbol_name = "sys_msgget",
		},
	},

	{
		.entry = jsys_msgsnd,
		.kp = {
			.symbol_name = "sys_msgsnd",
		},
	},

	{
		.entry = jsys_msgrcv,
		.kp = {
			.symbol_name = "sys_msgrcv",
		},
	},

	{
		.entry = jsys_msgctl,
		.kp = {
			.symbol_name = "sys_msgctl",
		},
	},

	{
		.entry = jsys_semget,
		.kp = {
			.symbol_name = "sys_semget",
		},
	},

	{
		.entry = jsys_semop,
		.kp = {
			.symbol_name = "sys_semop",
		},
	},

	{
		.entry = jsys_semctl,
		.kp = {
			.symbol_name = "sys_semctl",
		},
	},

	{
		.entry = jsys_semtimedop,
		.kp = {
			.symbol_name = "sys_semtimedop",
		},
	},
	

	/* // Returns -EINVAL (invalid argument - perhaps reregistering kprobe?)
	{
		.entry = jsys_shmat,
		.kp = {
			.symbol_name = "sys_shmat",
		},
	},
	*/
	
	{
		.entry = jsys_shmget,
		.kp = {
			.symbol_name = "sys_shmget",
		},
	},

	{
		.entry = jsys_shmdt,
		.kp = {
			.symbol_name = "sys_shmdt",
		},
	},

	{
		.entry = jsys_shmctl,
		.kp = {
			.symbol_name = "sys_shmctl",
		},
	},

	{
		.entry = jsys_ipc,
		.kp = {
			.symbol_name = "sys_ipc",
		},
	},

	{
		.entry = jsys_mq_open,
		.kp = {
			.symbol_name = "sys_mq_open",
		},
	},
	
	{
		.entry = jsys_mq_unlink,
		.kp = {
			.symbol_name = "sys_mq_unlink",
		},
	},

	{
		.entry = jsys_mq_timedsend,
		.kp = {
			.symbol_name = "sys_mq_timedsend",
		},
	},

	{
		.entry = jsys_mq_timedreceive,
		.kp = {
			.symbol_name = "sys_mq_timedreceive",
		},
	},

	{
		.entry = jsys_mq_notify,
		.kp = {
			.symbol_name = "sys_mq_notify",
		},
	},

	{
		.entry = jsys_mq_getsetattr,
		.kp = {
			.symbol_name = "sys_mq_getsetattr",
		},
	},

	/* // This returns -17 when register_jprobe is called
	{
		.entry = jsys_pciconfig_iobase,
		.kp = {
			.symbol_name = "sys_pciconfig_iobase",
		},
	},
	*/
	
	
	/* // This returns -17 when register_jprobe is called
	{
		.entry = jsys_pciconfig_read,
		.kp = {
			.symbol_name = "sys_pciconfig_read",
		},
	},
	*/

	/* // This returns -17 when register_jprobe is called
	{
		.entry = jsys_pciconfig_write,
		.kp = {
			.symbol_name = "sys_pciconfig_write",
		},
	},
	*/

	{
		.entry = jsys_prctl,
		.kp = {
			.symbol_name = "sys_prctl",
		},
	},

	{
		.entry = jsys_swapon,
		.kp = {
			.symbol_name = "sys_swapon",
		},
	},

	{
		.entry = jsys_swapoff,
		.kp = {
			.symbol_name = "sys_swapoff",
		},
	},
	
	{
		.entry = jsys_sysctl,
		.kp = {
			.symbol_name = "sys_sysctl",
		},
	},
	
	
	{
		.entry = jsys_sysinfo,
		.kp = {
			.symbol_name = "sys_sysinfo",
		},
	},
	
	{
		.entry = jsys_sysfs,
		.kp = {
			.symbol_name = "sys_sysfs",
		},
	},

	{
		.entry = jsys_syslog,
		.kp = {
			.symbol_name = "sys_syslog",
		},
	},

	{
		.entry = jsys_uselib,
		.kp = {
			.symbol_name = "sys_uselib",
		},
	},

	/* // Returns -17
	{
		.entry = jsys_ni_syscall,
		.kp = {
			.symbol_name = "sys_ni_syscall",
		},
	},
	*/

	{
		.entry = jsys_ptrace,
		.kp = {
			.symbol_name = "sys_ptrace",
		},
	},

	{
		.entry = jsys_add_key,
		.kp = {
			.symbol_name = "sys_add_key",
		},
	},

	{
		.entry = jsys_request_key,
		.kp = {
			.symbol_name = "sys_request_key",
		},
	},

	{
		.entry = jsys_keyctl,
		.kp = {
			.symbol_name = "sys_keyctl",
		},
	},

	{
		.entry = jsys_ioprio_set,
		.kp = {
			.symbol_name = "sys_ioprio_set",
		},
	},

	{
		.entry = jsys_ioprio_get,
		.kp = {
			.symbol_name = "sys_ioprio_get",
		},
	},
	
	
	{
		.entry = jsys_set_mempolicy,
		.kp = {
			.symbol_name = "sys_set_mempolicy",
		},
	},

	{
		.entry = jsys_migrate_pages,
		.kp = {
			.symbol_name = "sys_migrate_pages",
		},
	},

	{
		.entry = jsys_move_pages,
		.kp = {
			.symbol_name = "sys_move_pages",
		},
	},

	{
		.entry = jsys_mbind,
		.kp = {
			.symbol_name = "sys_mbind",
		},
	},

	{
		.entry = jsys_get_mempolicy,
		.kp = {
			.symbol_name = "sys_get_mempolicy",
		},
	},

	{
		.entry = jsys_inotify_init,
		.kp = {
			.symbol_name = "sys_inotify_init",
		},
	},

	{
		.entry = jsys_inotify_init1,
		.kp = {
			.symbol_name = "sys_inotify_init1",
		},
	},

	{
		.entry = jsys_inotify_add_watch,
		.kp = {
			.symbol_name = "sys_inotify_add_watch",
		},
	},

	{
		.entry = jsys_inotify_rm_watch,
		.kp = {
			.symbol_name = "sys_inotify_rm_watch",
		},
	},

	/* // Returned something wrong, not sure what - the system crashed too quickly to tell what the return value was
	{
		.entry = jsys_spu_run,
		.kp = {
			.symbol_name = "sys_spu_run",
		},
	},
	*/

	/* // Returns -17
	{
		.entry = jsys_spu_create,
		.kp = {
			.symbol_name = "sys_spu_create",
		},
	},
	*/

	{
		.entry = jsys_mknodat,
		.kp = {
			.symbol_name = "sys_mknodat",
		},
	},

	{
		.entry = jsys_mkdirat,
		.kp = {
			.symbol_name = "sys_mkdirat",
		},
	},

	{
		.entry = jsys_unlinkat,
		.kp = {
			.symbol_name = "sys_unlinkat",
		},
	},

	{
		.entry = jsys_symlinkat,
		.kp = {
			.symbol_name = "sys_symlinkat",
		},
	},

	{
		.entry = jsys_linkat,
		.kp = {
			.symbol_name = "sys_linkat",
		},
	},

	{
		.entry = jsys_renameat,
		.kp = {
			.symbol_name = "sys_renameat",
		},
	},

	{
		.entry = jsys_renameat2,
		.kp = {
			.symbol_name = "sys_renameat2",
		},
	},

	{
		.entry = jsys_futimesat,
		.kp = {
			.symbol_name = "sys_futimesat",
		},
	},

	{
		.entry = jsys_faccessat,
		.kp = {
			.symbol_name = "sys_faccessat",
		},
	},

	{
		.entry = jsys_fchmodat,
		.kp = {
			.symbol_name = "sys_fchmodat",
		},
	},

	{
		.entry = jsys_fchownat,
		.kp = {
			.symbol_name = "sys_fchownat",
		},
	},

	{
		.entry = jsys_openat,
		.kp = {
			.symbol_name = "sys_openat",
		},
	},

	{
		.entry = jsys_newfstatat,
		.kp = {
			.symbol_name = "sys_newfstatat",
		},
	},

	{
		.entry = jsys_readlinkat,
		.kp = {
			.symbol_name = "sys_readlinkat",
		},
	},

	{
		.entry = jsys_utimensat,
		.kp = {
			.symbol_name = "sys_utimensat",
		},
	},

	{
		.entry = jsys_unshare,
		.kp = {
			.symbol_name = "sys_unshare",
		},
	},

	{
		.entry = jsys_splice,
		.kp = {
			.symbol_name = "sys_splice",
		},
	},

	{
		.entry = jsys_vmsplice,
		.kp = {
			.symbol_name = "sys_vmsplice",
		},
	},

	{
		.entry = jsys_tee,
		.kp = {
			.symbol_name = "sys_tee",
		},
	},

	{
		.entry = jsys_sync_file_range,
		.kp = {
			.symbol_name = "sys_sync_file_range",
		},
	},

	{
		.entry = jsys_sync_file_range2,
		.kp = {
			.symbol_name = "sys_sync_file_range2",
		},
	},

	{
		.entry = jsys_get_robust_list,
		.kp = {
			.symbol_name = "sys_get_robust_list",
		},
	},

	{
		.entry = jsys_set_robust_list,
		.kp = {
			.symbol_name = "sys_set_robust_list",
		},
	},

	{
		.entry = jsys_getcpu,
		.kp = {
			.symbol_name = "sys_getcpu",
		},
	},

	{
		.entry = jsys_signalfd,
		.kp = {
			.symbol_name = "sys_signalfd",
		},
	},

	{
		.entry = jsys_signalfd4,
		.kp = {
			.symbol_name = "sys_signalfd4",
		},
	},

	{
		.entry = jsys_timerfd_create,
		.kp = {
			.symbol_name = "sys_timerfd_create",
		},
	},

	{
		.entry = jsys_timerfd_settime,
		.kp = {
			.symbol_name = "sys_timerfd_settime",
		},
	},

	{
		.entry = jsys_timerfd_gettime,
		.kp = {
			.symbol_name = "sys_timerfd_gettime",
		},
	},

	{
		.entry = jsys_eventfd,
		.kp = {
			.symbol_name = "sys_eventfd",
		},
	},

	{
		.entry = jsys_eventfd2,
		.kp = {
			.symbol_name = "sys_eventfd2",
		},
	},

	{
		.entry = jsys_memfd_create,
		.kp = {
			.symbol_name = "sys_memfd_create",
		},
	},

	{
		.entry = jsys_userfaultfd,
		.kp = {
			.symbol_name = "sys_userfaultfd",
		},
	},

	{
		.entry = jsys_fallocate,
		.kp = {
			.symbol_name = "sys_fallocate",
		},
	},

	{
		.entry = jsys_old_readdir,
		.kp = {
			.symbol_name = "sys_old_readdir",
		},
	},

	{
		.entry = jsys_pselect6,
		.kp = {
			.symbol_name = "sys_pselect6",
		},
	},

	{
		.entry = jsys_ppoll,
		.kp = {
			.symbol_name = "sys_ppoll",
		},
	},

	{
		.entry = jsys_fanotify_init,
		.kp = {
			.symbol_name = "sys_fanotify_init",
		},
	},

	{
		.entry = jsys_fanotify_mark,
		.kp = {
			.symbol_name = "sys_fanotify_mark",
		},
	},

	{
		.entry = jsys_syncfs,
		.kp = {
			.symbol_name = "sys_syncfs",
		},
	},
	
	
	{
		.entry = jsys_fork,
		.kp = {
			.symbol_name = "sys_fork",
		},
	},

	{
		.entry = jsys_vfork,
		.kp = {
			.symbol_name = "sys_vfork",
		},
	},

	
	{
		.entry = jsys_clone,
		.kp = {
			.symbol_name = "sys_clone",
		},
	},
	
	
	{
		.entry = jsys_execve,
		.kp = {
			.symbol_name = "sys_execve",
		},
	},
	
	{
		.entry = jsys_perf_event_open,
		.kp = {
			.symbol_name = "sys_perf_event_open",
		},
	},

	{
		.entry = jsys_mmap_pgoff,
		.kp = {
			.symbol_name = "sys_mmap_pgoff",
		},
	},

	/* // Returns -2
	{
		.entry = jsys_old_mmap,
		.kp = {
			.symbol_name = "sys_old_mmap",
		},
	},
	*/

	{
		.entry = jsys_name_to_handle_at,
		.kp = {
			.symbol_name = "sys_name_to_handle_at",
		},
	},

	{
		.entry = jsys_open_by_handle_at,
		.kp = {
			.symbol_name = "sys_open_by_handle_at",
		},
	},

	{
		.entry = jsys_setns,
		.kp = {
			.symbol_name = "sys_setns",
		},
	},

	{
		.entry = jsys_process_vm_readv,
		.kp = {
			.symbol_name = "sys_process_vm_readv",
		},
	},

	{
		.entry = jsys_process_vm_writev,
		.kp = {
			.symbol_name = "sys_process_vm_writev",
		},
	},
	
	
	{
		.entry = jsys_kcmp,
		.kp = {
			.symbol_name = "sys_kcmp",
		},
	},

	{
		.entry = jsys_finit_module,
		.kp = {
			.symbol_name = "sys_finit_module",
		},
	},

	{
		.entry = jsys_seccomp,
		.kp = {
			.symbol_name = "sys_seccomp",
		},
	},

	{
		.entry = jsys_getrandom,
		.kp = {
			.symbol_name = "sys_getrandom",
		},
	},

	{
		.entry = jsys_bpf,
		.kp = {
			.symbol_name = "sys_bpf",
		},
	},
	

	
	{
		.entry = jsys_execveat,
		.kp = {
			.symbol_name = "sys_execveat",
		},
	},

	{
		.entry = jsys_membarrier,
		.kp = {
			.symbol_name = "sys_membarrier",
		},
	},

	{
		.entry = jsys_copy_file_range,
		.kp = {
			.symbol_name = "sys_copy_file_range",
		},
	},

	{
		.entry = jsys_mlock2,
		.kp = {
			.symbol_name = "sys_mlock2",
		},
	},
		
	{
		.entry = jsys_pkey_mprotect,
		.kp = {
			.symbol_name = "sys_pkey_mprotect",
		},
	},

	{
		.entry = jsys_pkey_alloc,
		.kp = {
			.symbol_name = "sys_pkey_alloc",
		},
	},

	{
		.entry = jsys_pkey_free,
		.kp = {
			.symbol_name = "sys_pkey_free",
		},
	},
	
	
	/* // Anil believes this syscall may not exist
	{
		.entry = jsys_statx,
		.kp = {
			.symbol_name = "sys_statx",
		},
	}
	*/
};

#define num_syscalls (sizeof(jprobes_array) / sizeof(jprobes_array[0]))
