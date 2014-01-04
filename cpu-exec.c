/*
 *  emulator main execution loop
 *
 *  Copyright (c) 2003-2005 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include "config.h"
#include "cpu.h"
#include "disas.h"
#include "tcg.h"
#include "qemu-barrier.h"
#include "qtest.h"


int tb_invalidated_flag;

//#define CONFIG_DEBUG_EXEC
typedef struct Stub_obj Stub_obj;
struct Stub_obj {
    int next_pc;
    int prev_tb;
};

bool qemu_cpu_has_work(CPUState *cpu)
{
    return cpu_has_work(cpu);
}

void cpu_loop_exit(CPUArchState *env)
{
    //fprintf(stderr, "line:%d, func:%s\n", __LINE__, __func__);
    env->current_tb = NULL;
    longjmp(env->jmp_env, 1);
}

static TranslationBlock *tb_find_slow(CPUArchState *env,
                                      target_ulong pc,
                                      target_ulong cs_base,
                                      uint64_t flags)
{
    TranslationBlock *tb, **ptb1;
    unsigned int h;
    tb_page_addr_t phys_pc, phys_page1;
    target_ulong virt_page2;

    tb_invalidated_flag = 0;

    /* find translated block using physical mappings */
    phys_pc = get_page_addr_code(env, pc);
    phys_page1 = phys_pc & TARGET_PAGE_MASK;
    h = tb_phys_hash_func(phys_pc);
    ptb1 = &tb_phys_hash[h];
    for(;;) {
        tb = *ptb1;
        if (!tb)
            goto not_found;
        if (tb->pc == pc &&
            tb->page_addr[0] == phys_page1 &&
            tb->cs_base == cs_base &&
            tb->flags == flags) {
            /* check next page if needed */
            if (tb->page_addr[1] != -1) {
                tb_page_addr_t phys_page2;

                virt_page2 = (pc & TARGET_PAGE_MASK) +
                    TARGET_PAGE_SIZE;
                phys_page2 = get_page_addr_code(env, virt_page2);
                if (tb->page_addr[1] == phys_page2)
                    goto found;
            } else {
                goto found;
            }
        }
        ptb1 = &tb->phys_hash_next;
    }
 not_found:
   /* if no translated code available, then translate it now */
    tb = tb_gen_code(env, pc, cs_base, flags, 0);

 found:
    /* Move the last found TB to the head of the list */
    if (likely(*ptb1)) {
        *ptb1 = tb->phys_hash_next;
        tb->phys_hash_next = tb_phys_hash[h];
        tb_phys_hash[h] = tb;
    }
    /* we add the TB in the virtual pc hash table */
    env->tb_jmp_cache[tb_jmp_cache_hash_func(pc)] = tb;
    return tb;
}

static inline TranslationBlock *tb_find_fast(CPUArchState *env)
{
    TranslationBlock *tb;
    target_ulong cs_base, pc;
    int flags;

    /* we record a subset of the CPU state. It will
       always be the same before a given translated block
       is executed. */
    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
    tb = env->tb_jmp_cache[tb_jmp_cache_hash_func(pc)];
    if (unlikely(!tb || tb->pc != pc || tb->cs_base != cs_base ||
                 tb->flags != flags)) {
        tb = tb_find_slow(env, pc, cs_base, flags);
    }
    return tb;
}

/* main execution loop */

volatile sig_atomic_t exit_request;

int cpu_exec(CPUArchState *env)
{
    int ret;
    TranslationBlock *tb;
    uint8_t *tc_ptr;
    Stub_obj *cc_stub;
    tcg_target_ulong prev_tb;

    env->exception_index = -1;

    /* prepare setjmp context for exception handling */
    for(;;) {
        if (setjmp(env->jmp_env) == 0) {
            /* if an exception is pending, we execute it here */
            if (env->exception_index >= 0) {
                /* if user mode only, we simulate a fake exception
                   which will be handled outside the cpu execution
                   loop */
                ret = env->exception_index;
                break;
            }

            prev_tb = 0; /* force lookup of first TB */
            for(;;) {
#if defined(DEBUG_DISAS) || defined(CONFIG_DEBUG_EXEC)
                if (qemu_loglevel_mask(CPU_LOG_TB_CPU)) {
                    /* restore flags in standard format */
                    log_cpu_state(env, 0);
                }
#endif /* DEBUG_DISAS || CONFIG_DEBUG_EXEC */

                tb = tb_find_fast(env);

#ifdef CONFIG_DEBUG_EXEC
                qemu_log_mask(CPU_LOG_EXEC, "Trace %p [" TARGET_FMT_lx "] %s\n",
                             tb->tc_ptr, tb->pc,
                             lookup_symbol(tb->pc));
#endif

                /* see if we can patch the calling TB. When the TB
                   spans two pages, we cannot safely do a direct
                   jump. */
                if (prev_tb != 0 && tb->page_addr[1] == -1) {
                   // tb_add_jump((TranslationBlock *)(next_tb & ~3), next_tb & 3, tb);
                }

                /* cpu_interrupt might be called while translating the
                   TB, but before it is linked into a potentially
                   infinite loop and becomes env->current_tb. Avoid
                   starting execution if there is a pending interrupt. */
                env->current_tb = tb;
                /* the prologue is arm-mode */
                *env->cpsr = *env->cpsr & ~(1 << 5);

                /* in prologue, use [bx (tc_ptr | env->thumb)] to detemine 
                 * the cpu mode dynamicly
                 */
                tc_ptr = (uint32_t)tb->tc_ptr | env->thumb;
                if (tb->pc == 0x00011e90) {
                    fprintf(stderr, "tb->pc is 0x00011824. @%s\n", __FUNCTION__);
                }
                /* execute the generated code */
                fprintf(stderr, "tb->pc is. @%x\n", tb->pc);
                cc_stub = tcg_qemu_tb_exec(env, tc_ptr);
                /* handle cc_stub */
                *env->tpc = cc_stub->next_pc & ~1;
                env->prev_tb = cc_stub->prev_tb;
                if (((struct TranslationBlock *)env->prev_tb)->may_change_state) {
                    env->thumb = cc_stub->next_pc & 1;
                }
                prev_tb = env->prev_tb;

                if (*env->tpc == 0x00011e90) {
                    fprintf(stderr, "*env->tpc is 0x00011824. @%s\n", __FUNCTION__);
                }
                env->current_tb = NULL;
            } /* for(;;) */
        }
    } /* for(;;) */

    return ret;
}

