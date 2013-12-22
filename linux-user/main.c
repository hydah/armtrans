/*
 *  qemu user main
 *
 *  Copyright (c) 2003-2008 Fabrice Bellard
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/resource.h>

#include "qemu.h"
#include "qemu-common.h"
#include "cache-utils.h"
#include "cpu.h"
#include "tcg.h"
#include "qemu-timer.h"
#include "envlist.h"
#include "elf.h"

#define DEBUG_LOGFILE "/tmp/qemu.log"

char *exec_path;

int singlestep;
const char *filename;
const char *argv0;
int gdbstub_port;
envlist_t *envlist;
const char *cpu_model;
unsigned long mmap_min_addr;
#if defined(CONFIG_USE_GUEST_BASE)
unsigned long guest_base;
int have_guest_base;
#if (TARGET_LONG_BITS == 32) && (HOST_LONG_BITS == 64)
/*
 * When running 32-on-64 we should make sure we can fit all of the possible
 * guest address space into a contiguous chunk of virtual host memory.
 *
 * This way we will never overlap with our own libraries or binaries or stack
 * or anything else that QEMU maps.
 */
unsigned long reserved_va = 0xf7000000;
#else
unsigned long reserved_va;
#endif
#endif

static void usage(void);

static const char *interp_prefix = CONFIG_QEMU_INTERP_PREFIX;
const char *qemu_uname_release = CONFIG_UNAME_RELEASE;

/* XXX: on x86 MAP_GROWSDOWN only works if ESP <= address + 32, so
   we allocate a bigger stack. Need a better solution, for example
   by remapping the process stack directly at the right place */
unsigned long guest_stack_size = 8 * 1024 * 1024UL;

void gemu_log(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

#if defined(TARGET_I386)
int cpu_get_pic_interrupt(CPUX86State *env)
{
    return -1;
}
#endif

#if defined(CONFIG_USE_NPTL)
/***********************************************************/
/* Helper routines for implementing atomic operations.  */

/* To implement exclusive operations we force all cpus to syncronise.
   We don't require a full sync, only that no cpus are executing guest code.
   The alternative is to map target atomic ops onto host equivalents,
   which requires quite a lot of per host/target work.  */
static pthread_mutex_t cpu_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t exclusive_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t exclusive_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t exclusive_resume = PTHREAD_COND_INITIALIZER;
static int pending_cpus;

/* Make sure everything is in a consistent state for calling fork().  */
void fork_start(void)
{
    pthread_mutex_lock(&tb_lock);
    pthread_mutex_lock(&exclusive_lock);
    mmap_fork_start();
}

void fork_end(int child)
{
    mmap_fork_end(child);
    if (child) {
        /* Child processes created by fork() only have a single thread.
           Discard information about the parent threads.  */
        first_cpu = thread_env;
        thread_env->next_cpu = NULL;
        pending_cpus = 0;
        pthread_mutex_init(&exclusive_lock, NULL);
        pthread_mutex_init(&cpu_list_mutex, NULL);
        pthread_cond_init(&exclusive_cond, NULL);
        pthread_cond_init(&exclusive_resume, NULL);
        pthread_mutex_init(&tb_lock, NULL);
        gdbserver_fork(thread_env);
    } else {
        pthread_mutex_unlock(&exclusive_lock);
        pthread_mutex_unlock(&tb_lock);
    }
}

/* Wait for pending exclusive operations to complete.  The exclusive lock
   must be held.  */
static inline void exclusive_idle(void)
{
    while (pending_cpus) {
        pthread_cond_wait(&exclusive_resume, &exclusive_lock);
    }
}

/* Start an exclusive operation.
   Must only be called from outside cpu_arm_exec.   */
static inline void start_exclusive(void)
{
    CPUArchState *other;
    pthread_mutex_lock(&exclusive_lock);
    exclusive_idle();

    pending_cpus = 1;
    /* Make all other cpus stop executing.  */
    for (other = first_cpu; other; other = other->next_cpu) {
        if (other->running) {
            pending_cpus++;
            cpu_exit(other);
        }
    }
    if (pending_cpus > 1) {
        pthread_cond_wait(&exclusive_cond, &exclusive_lock);
    }
}

/* Finish an exclusive operation.  */
static inline void end_exclusive(void)
{
    pending_cpus = 0;
    pthread_cond_broadcast(&exclusive_resume);
    pthread_mutex_unlock(&exclusive_lock);
}

/* Wait for exclusive ops to finish, and begin cpu execution.  */
static inline void cpu_exec_start(CPUArchState *env)
{
    pthread_mutex_lock(&exclusive_lock);
    exclusive_idle();
    env->running = 1;
    pthread_mutex_unlock(&exclusive_lock);
}

/* Mark cpu as not executing, and release pending exclusive ops.  */
static inline void cpu_exec_end(CPUArchState *env)
{
    pthread_mutex_lock(&exclusive_lock);
    env->running = 0;
    if (pending_cpus > 1) {
        pending_cpus--;
        if (pending_cpus == 1) {
            pthread_cond_signal(&exclusive_cond);
        }
    }
    exclusive_idle();
    pthread_mutex_unlock(&exclusive_lock);
}

void cpu_list_lock(void)
{
    pthread_mutex_lock(&cpu_list_mutex);
}

void cpu_list_unlock(void)
{
    pthread_mutex_unlock(&cpu_list_mutex);
}
#else /* if !CONFIG_USE_NPTL */
/* These are no-ops because we are not threadsafe.  */
static inline void cpu_exec_start(CPUArchState *env)
{
}

static inline void cpu_exec_end(CPUArchState *env)
{
}

static inline void start_exclusive(void)
{
}

static inline void end_exclusive(void)
{
}

void fork_start(void)
{
}

void fork_end(int child)
{
    if (child) {
        gdbserver_fork(thread_env);
    }
}

void cpu_list_lock(void)
{
}

void cpu_list_unlock(void)
{
}
#endif



#ifdef TARGET_ARM

#define get_user_code_u32(x, gaddr, doswap)             \
    ({ abi_long __r = get_user_u32((x), (gaddr));       \
        if (!__r && (doswap)) {                         \
            (x) = bswap32(x);                           \
        }                                               \
        __r;                                            \
    })

#define get_user_code_u16(x, gaddr, doswap)             \
    ({ abi_long __r = get_user_u16((x), (gaddr));       \
        if (!__r && (doswap)) {                         \
            (x) = bswap16(x);                           \
        }                                               \
        __r;                                            \
    })

/*
 * See the Linux kernel's Documentation/arm/kernel_user_helpers.txt
 * Input:
 * r0 = pointer to oldval
 * r1 = pointer to newval
 * r2 = pointer to target value
 *
 * Output:
 * r0 = 0 if *ptr was changed, non-0 if no exchange happened
 * C set if *ptr was changed, clear if no exchange happened
 *
 * Note segv's in kernel helpers are a bit tricky, we can set the
 * data address sensibly but the PC address is just the entry point.
 */
static void arm_kernel_cmpxchg64_helper(CPUARMState *env)
{
    uint64_t oldval, newval, val;
    uint32_t addr, cpsr;
    target_siginfo_t info;

    /* Based on the 32 bit code in do_kernel_trap */

    /* XXX: This only works between threads, not between processes.
       It's probably possible to implement this with native host
       operations. However things like ldrex/strex are much harder so
       there's not much point trying.  */
    start_exclusive();
    cpsr = cpsr_read(env);
    addr = env->regs[2];

    if (get_user_u64(oldval, env->regs[0])) {
        env->cp15.c6_data = env->regs[0];
        goto segv;
    };

    if (get_user_u64(newval, env->regs[1])) {
        env->cp15.c6_data = env->regs[1];
        goto segv;
    };

    if (get_user_u64(val, addr)) {
        env->cp15.c6_data = addr;
        goto segv;
    }

    if (val == oldval) {
        val = newval;

        if (put_user_u64(val, addr)) {
            env->cp15.c6_data = addr;
            goto segv;
        };

        env->regs[0] = 0;
        cpsr |= CPSR_C;
    } else {
        env->regs[0] = -1;
        cpsr &= ~CPSR_C;
    }
    cpsr_write(env, cpsr, CPSR_C);
    end_exclusive();
    return;

segv:
    end_exclusive();
    /* We get the PC of the entry address - which is as good as anything,
       on a real kernel what you get depends on which mode it uses. */
    info.si_signo = SIGSEGV;
    info.si_errno = 0;
    /* XXX: check env->error_code */
    info.si_code = TARGET_SEGV_MAPERR;
    info._sifields._sigfault._addr = env->cp15.c6_data;
    queue_signal(env, info.si_signo, &info);

    end_exclusive();
}

/* Handle a jump to the kernel code page.  */
static int
do_kernel_trap(CPUARMState *env)
{
    uint32_t addr;
    uint32_t cpsr;
    uint32_t val;

    switch (env->regs[15]) {
    case 0xffff0fa0: /* __kernel_memory_barrier */
        /* ??? No-op. Will need to do better for SMP.  */
        break;
    case 0xffff0fc0: /* __kernel_cmpxchg */
         /* XXX: This only works between threads, not between processes.
            It's probably possible to implement this with native host
            operations. However things like ldrex/strex are much harder so
            there's not much point trying.  */
        start_exclusive();
        cpsr = cpsr_read(env);
        addr = env->regs[2];
        /* FIXME: This should SEGV if the access fails.  */
        if (get_user_u32(val, addr))
            val = ~env->regs[0];
        if (val == env->regs[0]) {
            val = env->regs[1];
            /* FIXME: Check for segfaults.  */
            put_user_u32(val, addr);
            env->regs[0] = 0;
            cpsr |= CPSR_C;
        } else {
            env->regs[0] = -1;
            cpsr &= ~CPSR_C;
        }
        cpsr_write(env, cpsr, CPSR_C);
        end_exclusive();
        break;
    case 0xffff0fe0: /* __kernel_get_tls */
        env->regs[0] = env->cp15.c13_tls2;
        break;
    case 0xffff0f60: /* __kernel_cmpxchg64 */
        arm_kernel_cmpxchg64_helper(env);
        break;

    default:
        return 1;
    }
    /* Jump back to the caller.  */
    addr = env->regs[14];
    if (addr & 1) {
        env->thumb = 1;
        addr &= ~1;
    }
    env->regs[15] = addr;

    return 0;
}

static int do_strex(CPUARMState *env)
{
    uint32_t val;
    int size;
    int rc = 1;
    int segv = 0;
    uint32_t addr;
    start_exclusive();
    addr = env->exclusive_addr;
    if (addr != env->exclusive_test) {
        goto fail;
    }
    size = env->exclusive_info & 0xf;
    switch (size) {
    case 0:
        segv = get_user_u8(val, addr);
        break;
    case 1:
        segv = get_user_u16(val, addr);
        break;
    case 2:
    case 3:
        segv = get_user_u32(val, addr);
        break;
    default:
        abort();
    }
    if (segv) {
        env->cp15.c6_data = addr;
        goto done;
    }
    if (val != env->exclusive_val) {
        goto fail;
    }
    if (size == 3) {
        segv = get_user_u32(val, addr + 4);
        if (segv) {
            env->cp15.c6_data = addr + 4;
            goto done;
        }
        if (val != env->exclusive_high) {
            goto fail;
        }
    }
    val = env->regs[(env->exclusive_info >> 8) & 0xf];
    switch (size) {
    case 0:
        segv = put_user_u8(val, addr);
        break;
    case 1:
        segv = put_user_u16(val, addr);
        break;
    case 2:
    case 3:
        segv = put_user_u32(val, addr);
        break;
    }
    if (segv) {
        env->cp15.c6_data = addr;
        goto done;
    }
    if (size == 3) {
        val = env->regs[(env->exclusive_info >> 12) & 0xf];
        segv = put_user_u32(val, addr + 4);
        if (segv) {
            env->cp15.c6_data = addr + 4;
            goto done;
        }
    }
    rc = 0;
fail:
    env->regs[15] += 4;
    env->regs[(env->exclusive_info >> 4) & 0xf] = rc;
done:
    end_exclusive();
    return segv;
}

void cpu_loop(CPUARMState *env)
{
    int trapnr;
    unsigned int n, insn;
    target_siginfo_t info;
    uint32_t addr;


    for(;;) {
        cpu_exec_start(env);
        trapnr = cpu_arm_exec(env);
        cpu_exec_end(env);
        switch(trapnr) {
        case EXCP_UDEF:
            {
                TaskState *ts = env->opaque;
                uint32_t opcode;
                int rc;

                /* we handle the FPU emulation here, as Linux */
                /* we get the opcode */
                /* FIXME - what to do if get_user() fails? */
                get_user_code_u32(opcode, env->regs[15], env->bswap_code);

                rc = EmulateAll(opcode, &ts->fpa, env);
                if (rc == 0) { /* illegal instruction */
                    info.si_signo = SIGILL;
                    info.si_errno = 0;
                    info.si_code = TARGET_ILL_ILLOPN;
                    info._sifields._sigfault._addr = env->regs[15];
                    queue_signal(env, info.si_signo, &info);
                } else if (rc < 0) { /* FP exception */
                    int arm_fpe=0;

                    /* translate softfloat flags to FPSR flags */
                    if (-rc & float_flag_invalid)
                      arm_fpe |= BIT_IOC;
                    if (-rc & float_flag_divbyzero)
                      arm_fpe |= BIT_DZC;
                    if (-rc & float_flag_overflow)
                      arm_fpe |= BIT_OFC;
                    if (-rc & float_flag_underflow)
                      arm_fpe |= BIT_UFC;
                    if (-rc & float_flag_inexact)
                      arm_fpe |= BIT_IXC;

                    FPSR fpsr = ts->fpa.fpsr;
                    //printf("fpsr 0x%x, arm_fpe 0x%x\n",fpsr,arm_fpe);

                    if (fpsr & (arm_fpe << 16)) { /* exception enabled? */
                      info.si_signo = SIGFPE;
                      info.si_errno = 0;

                      /* ordered by priority, least first */
                      if (arm_fpe & BIT_IXC) info.si_code = TARGET_FPE_FLTRES;
                      if (arm_fpe & BIT_UFC) info.si_code = TARGET_FPE_FLTUND;
                      if (arm_fpe & BIT_OFC) info.si_code = TARGET_FPE_FLTOVF;
                      if (arm_fpe & BIT_DZC) info.si_code = TARGET_FPE_FLTDIV;
                      if (arm_fpe & BIT_IOC) info.si_code = TARGET_FPE_FLTINV;

                      info._sifields._sigfault._addr = env->regs[15];
                      queue_signal(env, info.si_signo, &info);
                    } else {
                      env->regs[15] += 4;
                    }

                    /* accumulate unenabled exceptions */
                    if ((!(fpsr & BIT_IXE)) && (arm_fpe & BIT_IXC))
                      fpsr |= BIT_IXC;
                    if ((!(fpsr & BIT_UFE)) && (arm_fpe & BIT_UFC))
                      fpsr |= BIT_UFC;
                    if ((!(fpsr & BIT_OFE)) && (arm_fpe & BIT_OFC))
                      fpsr |= BIT_OFC;
                    if ((!(fpsr & BIT_DZE)) && (arm_fpe & BIT_DZC))
                      fpsr |= BIT_DZC;
                    if ((!(fpsr & BIT_IOE)) && (arm_fpe & BIT_IOC))
                      fpsr |= BIT_IOC;
                    ts->fpa.fpsr=fpsr;
                } else { /* everything OK */
                    /* increment PC */
                    env->regs[15] += 4;
                }
            }
            break;
        case EXCP_SWI:
        case EXCP_BKPT:
            {
                env->eabi = 1;
                /* system call */
                if (trapnr == EXCP_BKPT) {
                    if (env->thumb) {
                        /* FIXME - what to do if get_user() fails? */
                        get_user_code_u16(insn, env->regs[15], env->bswap_code);
                        n = insn & 0xff;
                        env->regs[15] += 2;
                    } else {
                        /* FIXME - what to do if get_user() fails? */
                        get_user_code_u32(insn, env->regs[15], env->bswap_code);
                        n = (insn & 0xf) | ((insn >> 4) & 0xff0);
                        env->regs[15] += 4;
                    }
                } else {
                    if (env->thumb) {
                        /* FIXME - what to do if get_user() fails? */
                        get_user_code_u16(insn, env->regs[15] - 2,
                                          env->bswap_code);
                        n = insn & 0xff;
                    } else {
                        /* FIXME - what to do if get_user() fails? */
                        get_user_code_u32(insn, env->regs[15] - 4,
                                          env->bswap_code);
                        n = insn & 0xffffff;
                    }
                }

                if (n == ARM_NR_cacheflush) {
                    /* nop */
                } else if (n == ARM_NR_semihosting
                           || n == ARM_NR_thumb_semihosting) {
                    env->regs[0] = do_arm_semihosting (env);
                } else if (n == 0 || n >= ARM_SYSCALL_BASE || env->thumb) {
                    /* linux syscall */
                    if (env->thumb || n == 0) {
                        n = env->regs[7];
                    } else {
                        n -= ARM_SYSCALL_BASE;
                        env->eabi = 0;
                    }
                    if ( n > ARM_NR_BASE) {
                        switch (n) {
                        case ARM_NR_cacheflush:
                            /* nop */
                            break;
                        case ARM_NR_set_tls:
                            cpu_set_tls(env, env->regs[0]);
                            env->regs[0] = 0;
                            break;
                        default:
                            gemu_log("qemu: Unsupported ARM syscall: 0x%x\n",
                                     n);
                            env->regs[0] = -TARGET_ENOSYS;
                            break;
                        }
                    } else {
                        env->regs[0] = do_syscall(env,
                                                  n,
                                                  env->regs[0],
                                                  env->regs[1],
                                                  env->regs[2],
                                                  env->regs[3],
                                                  env->regs[4],
                                                  env->regs[5],
                                                  0, 0);
                    }
                } else {
                    goto error;
                }
            }
            break;
        case EXCP_INTERRUPT:
            /* just indicate that signals should be handled asap */
            break;
        case EXCP_PREFETCH_ABORT:
            addr = env->cp15.c6_insn;
            goto do_segv;
        case EXCP_DATA_ABORT:
            addr = env->cp15.c6_data;
        do_segv:
            {
                info.si_signo = SIGSEGV;
                info.si_errno = 0;
                /* XXX: check env->error_code */
                info.si_code = TARGET_SEGV_MAPERR;
                info._sifields._sigfault._addr = addr;
                queue_signal(env, info.si_signo, &info);
            }
            break;
        case EXCP_DEBUG:
            {
                int sig;

                sig = gdb_handlesig (env, TARGET_SIGTRAP);
                if (sig)
                  {
                    info.si_signo = sig;
                    info.si_errno = 0;
                    info.si_code = TARGET_TRAP_BRKPT;
                    queue_signal(env, info.si_signo, &info);
                  }
            }
            break;
        case EXCP_KERNEL_TRAP:
            if (do_kernel_trap(env))
              goto error;
            break;
        case EXCP_STREX:
            if (do_strex(env)) {
                addr = env->cp15.c6_data;
                goto do_segv;
            }
            break;
        default:
        error:
            fprintf(stderr, "qemu: unhandled CPU exception 0x%x - aborting\n",
                    trapnr);
            cpu_dump_state(env, stderr, fprintf, 0);
            abort();
        }
        process_pending_signals(env);
    }
}

#endif



THREAD CPUArchState *thread_env;

void task_settid(TaskState *ts)
{
    if (ts->ts_tid == 0) {
#ifdef CONFIG_USE_NPTL
        ts->ts_tid = (pid_t)syscall(SYS_gettid);
#else
        /* when no threads are used, tid becomes pid */
        ts->ts_tid = getpid();
#endif
    }
}

void stop_all_tasks(void)
{
    /*
     * We trust that when using NPTL, start_exclusive()
     * handles thread stopping correctly.
     */
    start_exclusive();
}

/* Assumes contents are already zeroed.  */
void init_task_state(TaskState *ts)
{
    int i;
 
    ts->used = 1;
    ts->first_free = ts->sigqueue_table;
    for (i = 0; i < MAX_SIGQUEUE_SIZE - 1; i++) {
        ts->sigqueue_table[i].next = &ts->sigqueue_table[i + 1];
    }
    ts->sigqueue_table[i].next = NULL;
}

static void handle_arg_help(const char *arg)
{
    usage();
}

static void handle_arg_log(const char *arg)
{
    int mask;
    const CPULogItem *item;

    mask = cpu_str_to_log_mask(arg);
    if (!mask) {
        printf("Log items (comma separated):\n");
        for (item = cpu_log_items; item->mask != 0; item++) {
            printf("%-10s %s\n", item->name, item->help);
        }
        exit(1);
    }
    cpu_set_log(mask);
}

static void handle_arg_log_filename(const char *arg)
{
    cpu_set_log_filename(arg);
}

static void handle_arg_set_env(const char *arg)
{
    char *r, *p, *token;
    r = p = strdup(arg);
    while ((token = strsep(&p, ",")) != NULL) {
        if (envlist_setenv(envlist, token) != 0) {
            usage();
        }
    }
    free(r);
}

static void handle_arg_unset_env(const char *arg)
{
    char *r, *p, *token;
    r = p = strdup(arg);
    while ((token = strsep(&p, ",")) != NULL) {
        if (envlist_unsetenv(envlist, token) != 0) {
            usage();
        }
    }
    free(r);
}

static void handle_arg_argv0(const char *arg)
{
    argv0 = strdup(arg);
}

static void handle_arg_stack_size(const char *arg)
{
    char *p;
    guest_stack_size = strtoul(arg, &p, 0);
    if (guest_stack_size == 0) {
        usage();
    }

    if (*p == 'M') {
        guest_stack_size *= 1024 * 1024;
    } else if (*p == 'k' || *p == 'K') {
        guest_stack_size *= 1024;
    }
}

static void handle_arg_ld_prefix(const char *arg)
{
    interp_prefix = strdup(arg);
}

static void handle_arg_pagesize(const char *arg)
{
    qemu_host_page_size = atoi(arg);
    if (qemu_host_page_size == 0 ||
        (qemu_host_page_size & (qemu_host_page_size - 1)) != 0) {
        fprintf(stderr, "page size must be a power of two\n");
        exit(1);
    }
}

static void handle_arg_gdb(const char *arg)
{
    gdbstub_port = atoi(arg);
}

static void handle_arg_uname(const char *arg)
{
    qemu_uname_release = strdup(arg);
}

static void handle_arg_cpu(const char *arg)
{
    cpu_model = strdup(arg);
    if (cpu_model == NULL || is_help_option(cpu_model)) {
        /* XXX: implement xxx_cpu_list for targets that still miss it */
#if defined(cpu_list)
        cpu_list(stdout, &fprintf);
#endif
        exit(1);
    }
}

#if defined(CONFIG_USE_GUEST_BASE)
static void handle_arg_guest_base(const char *arg)
{
    guest_base = strtol(arg, NULL, 0);
    have_guest_base = 1;
}

static void handle_arg_reserved_va(const char *arg)
{
    char *p;
    int shift = 0;
    reserved_va = strtoul(arg, &p, 0);
    switch (*p) {
    case 'k':
    case 'K':
        shift = 10;
        break;
    case 'M':
        shift = 20;
        break;
    case 'G':
        shift = 30;
        break;
    }
    if (shift) {
        unsigned long unshifted = reserved_va;
        p++;
        reserved_va <<= shift;
        if (((reserved_va >> shift) != unshifted)
#if HOST_LONG_BITS > TARGET_VIRT_ADDR_SPACE_BITS
            || (reserved_va > (1ul << TARGET_VIRT_ADDR_SPACE_BITS))
#endif
            ) {
            fprintf(stderr, "Reserved virtual address too big\n");
            exit(1);
        }
    }
    if (*p) {
        fprintf(stderr, "Unrecognised -R size suffix '%s'\n", p);
        exit(1);
    }
}
#endif

static void handle_arg_singlestep(const char *arg)
{
    singlestep = 1;
}

static void handle_arg_strace(const char *arg)
{
    do_strace = 1;
}

static void handle_arg_version(const char *arg)
{
    printf("qemu-" TARGET_ARCH " version " QEMU_VERSION QEMU_PKGVERSION
           ", Copyright (c) 2003-2008 Fabrice Bellard\n");
    exit(0);
}

struct qemu_argument {
    const char *argv;
    const char *env;
    bool has_arg;
    void (*handle_opt)(const char *arg);
    const char *example;
    const char *help;
};

static const struct qemu_argument arg_table[] = {
    {"h",          "",                 false, handle_arg_help,
     "",           "print this help"},
    {"g",          "QEMU_GDB",         true,  handle_arg_gdb,
     "port",       "wait gdb connection to 'port'"},
    {"L",          "QEMU_LD_PREFIX",   true,  handle_arg_ld_prefix,
     "path",       "set the elf interpreter prefix to 'path'"},
    {"s",          "QEMU_STACK_SIZE",  true,  handle_arg_stack_size,
     "size",       "set the stack size to 'size' bytes"},
    {"cpu",        "QEMU_CPU",         true,  handle_arg_cpu,
     "model",      "select CPU (-cpu help for list)"},
    {"E",          "QEMU_SET_ENV",     true,  handle_arg_set_env,
     "var=value",  "sets targets environment variable (see below)"},
    {"U",          "QEMU_UNSET_ENV",   true,  handle_arg_unset_env,
     "var",        "unsets targets environment variable (see below)"},
    {"0",          "QEMU_ARGV0",       true,  handle_arg_argv0,
     "argv0",      "forces target process argv[0] to be 'argv0'"},
    {"r",          "QEMU_UNAME",       true,  handle_arg_uname,
     "uname",      "set qemu uname release string to 'uname'"},
#if defined(CONFIG_USE_GUEST_BASE)
    {"B",          "QEMU_GUEST_BASE",  true,  handle_arg_guest_base,
     "address",    "set guest_base address to 'address'"},
    {"R",          "QEMU_RESERVED_VA", true,  handle_arg_reserved_va,
     "size",       "reserve 'size' bytes for guest virtual address space"},
#endif
    {"d",          "QEMU_LOG",         true,  handle_arg_log,
     "options",    "activate log"},
    {"D",          "QEMU_LOG_FILENAME", true, handle_arg_log_filename,
     "logfile",     "override default logfile location"},
    {"p",          "QEMU_PAGESIZE",    true,  handle_arg_pagesize,
     "pagesize",   "set the host page size to 'pagesize'"},
    {"singlestep", "QEMU_SINGLESTEP",  false, handle_arg_singlestep,
     "",           "run in singlestep mode"},
    {"strace",     "QEMU_STRACE",      false, handle_arg_strace,
     "",           "log system calls"},
    {"version",    "QEMU_VERSION",     false, handle_arg_version,
     "",           "display version information and exit"},
    {NULL, NULL, false, NULL, NULL, NULL}
};

static void usage(void)
{
    const struct qemu_argument *arginfo;
    int maxarglen;
    int maxenvlen;

    printf("usage: qemu-" TARGET_ARCH " [options] program [arguments...]\n"
           "Linux CPU emulator (compiled for " TARGET_ARCH " emulation)\n"
           "\n"
           "Options and associated environment variables:\n"
           "\n");

    maxarglen = maxenvlen = 0;

    for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
        if (strlen(arginfo->env) > maxenvlen) {
            maxenvlen = strlen(arginfo->env);
        }
        if (strlen(arginfo->argv) > maxarglen) {
            maxarglen = strlen(arginfo->argv);
        }
    }

    printf("%-*s%-*sDescription\n", maxarglen+3, "Argument",
            maxenvlen+1, "Env-variable");

    for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
        if (arginfo->has_arg) {
            printf("-%s %-*s %-*s %s\n", arginfo->argv,
                    (int)(maxarglen-strlen(arginfo->argv)), arginfo->example,
                    maxenvlen, arginfo->env, arginfo->help);
        } else {
            printf("-%-*s %-*s %s\n", maxarglen+1, arginfo->argv,
                    maxenvlen, arginfo->env,
                    arginfo->help);
        }
    }

    printf("\n"
           "Defaults:\n"
           "QEMU_LD_PREFIX  = %s\n"
           "QEMU_STACK_SIZE = %ld byte\n"
           "QEMU_LOG        = %s\n",
           interp_prefix,
           guest_stack_size,
           DEBUG_LOGFILE);

    printf("\n"
           "You can use -E and -U options or the QEMU_SET_ENV and\n"
           "QEMU_UNSET_ENV environment variables to set and unset\n"
           "environment variables for the target process.\n"
           "It is possible to provide several variables by separating them\n"
           "by commas in getsubopt(3) style. Additionally it is possible to\n"
           "provide the -E and -U options multiple times.\n"
           "The following lines are equivalent:\n"
           "    -E var1=val2 -E var2=val2 -U LD_PRELOAD -U LD_DEBUG\n"
           "    -E var1=val2,var2=val2 -U LD_PRELOAD,LD_DEBUG\n"
           "    QEMU_SET_ENV=var1=val2,var2=val2 QEMU_UNSET_ENV=LD_PRELOAD,LD_DEBUG\n"
           "Note that if you provide several changes to a single variable\n"
           "the last change will stay in effect.\n");

    exit(1);
}

static int parse_args(int argc, char **argv)
{
    const char *r;
    int optind;
    const struct qemu_argument *arginfo;

    for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
        if (arginfo->env == NULL) {
            continue;
        }

        r = getenv(arginfo->env);
        if (r != NULL) {
            arginfo->handle_opt(r);
        }
    }

    optind = 1;
    for (;;) {
        if (optind >= argc) {
            break;
        }
        r = argv[optind];
        if (r[0] != '-') {
            break;
        }
        optind++;
        r++;
        if (!strcmp(r, "-")) {
            break;
        }

        for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
            if (!strcmp(r, arginfo->argv)) {
                if (arginfo->has_arg) {
                    if (optind >= argc) {
                        usage();
                    }
                    arginfo->handle_opt(argv[optind]);
                    optind++;
                } else {
                    arginfo->handle_opt(NULL);
                }
                break;
            }
        }

        /* no option matched the current argv */
        if (arginfo->handle_opt == NULL) {
            usage();
        }
    }

    if (optind >= argc) {
        usage();
    }

    filename = argv[optind];
    exec_path = argv[optind];

    return optind;
}

int main(int argc, char **argv, char **envp)
{
    const char *log_file = DEBUG_LOGFILE;
    struct target_pt_regs regs1, *regs = &regs1;
    struct image_info info1, *info = &info1;
    struct linux_binprm bprm;
    TaskState *ts;
    CPUArchState *env;
    int optind;
    char **target_environ, **wrk;
    char **target_argv;
    int target_argc;
    int i;
    int ret;

    module_call_init(MODULE_INIT_QOM);

    qemu_cache_utils_init(envp);

    if ((envlist = envlist_create()) == NULL) {
        (void) fprintf(stderr, "Unable to allocate envlist\n");
        exit(1);
    }

    /* add current environment into the list */
    for (wrk = environ; *wrk != NULL; wrk++) {
        (void) envlist_setenv(envlist, *wrk);
    }

    /* Read the stack limit from the kernel.  If it's "unlimited",
       then we can do little else besides use the default.  */
    {
        struct rlimit lim;
        if (getrlimit(RLIMIT_STACK, &lim) == 0
            && lim.rlim_cur != RLIM_INFINITY
            && lim.rlim_cur == (target_long)lim.rlim_cur) {
            guest_stack_size = lim.rlim_cur;
        }
    }

    cpu_model = NULL;
#if defined(cpudef_setup)
    cpudef_setup(); /* parse cpu definitions in target config file (TBD) */
#endif

    /* init debug */
    cpu_set_log_filename(log_file);
    optind = parse_args(argc, argv);

    /* Zero out regs */
    memset(regs, 0, sizeof(struct target_pt_regs));

    /* Zero out image_info */
    memset(info, 0, sizeof(struct image_info));

    memset(&bprm, 0, sizeof (bprm));

    /* Scan interp_prefix dir for replacement files. */
    init_paths(interp_prefix);

    if (cpu_model == NULL) {
        cpu_model = "any";
    }
    tcg_exec_init(0);
    cpu_exec_init_all();
    /* NOTE: we need to init the CPU at this stage to get
       qemu_host_page_size */
    fprintf(stderr, "cpu_model is %x\n", cpu_model);
    env = cpu_init(cpu_model);
    if (!env) {
        fprintf(stderr, "Unable to find CPU definition\n");
        exit(1);
    }

    thread_env = env;

    if (getenv("QEMU_STRACE")) {
        do_strace = 1;
    }

    target_environ = envlist_to_environ(envlist, NULL);
    envlist_free(envlist);

#if defined(CONFIG_USE_GUEST_BASE)
    /*
     * Now that page sizes are configured in cpu_init() we can do
     * proper page alignment for guest_base.
     */
    guest_base = HOST_PAGE_ALIGN(guest_base);

    if (reserved_va || have_guest_base) {
        guest_base = init_guest_space(guest_base, reserved_va, 0,
                                      have_guest_base);
        if (guest_base == (unsigned long)-1) {
            fprintf(stderr, "Unable to reserve 0x%lx bytes of virtual address "
                    "space for use as guest address space (check your virtual "
                    "memory ulimit setting or reserve less using -R option)\n",
                    reserved_va);
            exit(1);
        }

        if (reserved_va) {
            mmap_next_start = reserved_va;
        }
    }
#endif /* CONFIG_USE_GUEST_BASE */

    /*
     * Read in mmap_min_addr kernel parameter.  This value is used
     * When loading the ELF image to determine whether guest_base
     * is needed.  It is also used in mmap_find_vma.
     */
    {
        FILE *fp;

        if ((fp = fopen("/proc/sys/vm/mmap_min_addr", "r")) != NULL) {
            unsigned long tmp;
            if (fscanf(fp, "%lu", &tmp) == 1) {
                mmap_min_addr = tmp;
                qemu_log("host mmap_min_addr=0x%lx\n", mmap_min_addr);
            }
            fclose(fp);
        }
    }

    /*
     * Prepare copy of argv vector for target.
     */
    target_argc = argc - optind;
    target_argv = calloc(target_argc + 1, sizeof (char *));
    if (target_argv == NULL) {
	(void) fprintf(stderr, "Unable to allocate memory for target_argv\n");
	exit(1);
    }

    /*
     * If argv0 is specified (using '-0' switch) we replace
     * argv[0] pointer with the given one.
     */
    i = 0;
    if (argv0 != NULL) {
        target_argv[i++] = strdup(argv0);
    }
    for (; i < target_argc; i++) {
        target_argv[i] = strdup(argv[optind + i]);
    }
    target_argv[target_argc] = NULL;

    ts = g_malloc0 (sizeof(TaskState));
    init_task_state(ts);
    /* build Task State */
    ts->info = info;
    ts->bprm = &bprm;
    env->opaque = ts;
    task_settid(ts);

    ret = loader_exec(filename, target_argv, target_environ, regs,
        info, &bprm);
    if (ret != 0) {
        printf("Error while loading %s: %s\n", filename, strerror(-ret));
        _exit(1);
    }

    for (wrk = target_environ; *wrk; wrk++) {
        free(*wrk);
    }

    free(target_environ);

    if (qemu_log_enabled()) {
#if defined(CONFIG_USE_GUEST_BASE)
        qemu_log("guest_base  0x%lx\n", guest_base);
#endif
        log_page_dump();

        qemu_log("start_brk   0x" TARGET_ABI_FMT_lx "\n", info->start_brk);
        qemu_log("end_code    0x" TARGET_ABI_FMT_lx "\n", info->end_code);
        qemu_log("start_code  0x" TARGET_ABI_FMT_lx "\n",
                 info->start_code);
        qemu_log("start_data  0x" TARGET_ABI_FMT_lx "\n",
                 info->start_data);
        qemu_log("end_data    0x" TARGET_ABI_FMT_lx "\n", info->end_data);
        qemu_log("start_stack 0x" TARGET_ABI_FMT_lx "\n",
                 info->start_stack);
        qemu_log("brk         0x" TARGET_ABI_FMT_lx "\n", info->brk);
        qemu_log("entry       0x" TARGET_ABI_FMT_lx "\n", info->entry);
    }

    target_set_brk(info->brk);
    syscall_init();
    signal_init();

#if defined(CONFIG_USE_GUEST_BASE)
    /* Now that we've loaded the binary, GUEST_BASE is fixed.  Delay
       generating the prologue until now so that the prologue can take
       the real value of GUEST_BASE into account.  */
    //tcg_prologue_init(&tcg_ctx);
#endif
    cc_prolog_init(env, &tcg_ctx);

    {
        int i;
        cpsr_write(env, regs->uregs[16], 0xffffffff);
        /* add by heyu.
         * set the guest program's cpsr
         */
        *env->cpsr = cpsr_read(env);
        for(i = 0; i < 16; i++) {
            env->regs[i] = regs->uregs[i];
        }
        /* Enable BE8.  */
        if (EF_ARM_EABI_VERSION(info->elf_flags) >= EF_ARM_EABI_VER4
            && (info->elf_flags & EF_ARM_BE8)) {
            env->bswap_code = 1;
        }
    }

#if defined(TARGET_ARM) || defined(TARGET_M68K) || defined(TARGET_UNICORE32)
    ts->stack_base = info->start_stack;
    ts->heap_base = info->brk;
    /* This will be filled in on the first SYS_HEAPINFO call.  */
    ts->heap_limit = 0;
#endif

    if (gdbstub_port) {
        if (gdbserver_start(gdbstub_port) < 0) {
            fprintf(stderr, "qemu: could not open gdbserver on port %d\n",
                    gdbstub_port);
            exit(1);
        }
        gdb_handlesig(env, 0);
    }
    cpu_loop(env);
    /* never exits */
    return 0;
}
