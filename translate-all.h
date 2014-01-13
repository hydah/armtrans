/*
 * Translated block handling 
 *
 * Copyright (c) 2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "qemu-common.h"

/* Target word size (must be identical to pointer size). */
#if UINTPTR_MAX == UINT32_MAX
# define TCG_TARGET_REG_BITS 32
#elif UINTPTR_MAX == UINT64_MAX
# define TCG_TARGET_REG_BITS 64
#else
# error Unknown pointer size for tcg target
#endif

#if TCG_TARGET_REG_BITS == 32
typedef int32_t tcg_target_long;
typedef uint32_t tcg_target_ulong;
#define TCG_PRIlx PRIx32
#define TCG_PRIld PRId32
#elif TCG_TARGET_REG_BITS == 64
typedef int64_t tcg_target_long;
typedef uint64_t tcg_target_ulong;
#define TCG_PRIlx PRIx64
#define TCG_PRIld PRId64
#else
#error unsupported
#endif

enum tb_type {
    DATA_TRA = 1,
    DATA_PRO,
    BRANCH,
    EXCEPTION,
};


typedef struct TCGContext TCGContext;

struct TCGContext {

    /* goto_tb support */
    uintptr_t *tb_next;
    uint16_t *tb_next_offset;
    uint16_t *tb_jmp_offset; /* != NULL if USE_DIRECT_JUMP */

    struct TranslationBlock *cur_tb;

    uint8_t *code_buf;
    uint8_t *code_ptr;
    uint8_t *tb_ret_addr;
    bool is_pop_pc;
    int condexec_mask;
    int condexec_cond;
    int condjmp;
    int condlabel;
    int is_jmp;
};

extern TCGContext tcg_ctx;



#define TCG_MAX_OP_ARGS 16

#define tcg_abort() \
do {\
    fprintf(stderr, "%s:%d: tcg fatal error\n", __FILE__, __LINE__);\
    abort();\
} while (0)


extern uint8_t *code_gen_prologue;

/* TCG targets may use a different definition of tcg_qemu_tb_exec. */
#if !defined(tcg_qemu_tb_exec)
# define tcg_qemu_tb_exec(env, tb_ptr) \
    ((tcg_target_ulong (*)(void *, void *))code_gen_prologue)(env, tb_ptr)
#endif

static inline void flush_icache_range(tcg_target_ulong start,
        tcg_target_ulong stop)
{
#if QEMU_GNUC_PREREQ(4, 1)
    __builtin___clear_cache((char *) start, (char *) stop);
#else
    register unsigned long _beg __asm ("a1") = start;
    register unsigned long _end __asm ("a2") = stop;
    register unsigned long _flg __asm ("a3") = 0;
    __asm __volatile__ ("swi 0x9f0002" : : "r" (_beg), "r" (_end), "r" (_flg));
#endif
}
