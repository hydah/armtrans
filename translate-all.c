/*
 *  Host code generation
 *
 *  Copyright (c) 2003 Fabrice Bellard
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
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "config.h"

#define NO_CPU_IO_DEFS
#include "cpu.h"
#include "disas.h"
#include "translate-all.h"
#include "qemu-timer.h"
#include "decode.h"


/* code generation context */
TCGContext tcg_ctx;

target_ulong gen_opc_pc[OPC_BUF_SIZE];
uint16_t gen_opc_icount[OPC_BUF_SIZE];
uint8_t gen_opc_instr_start[OPC_BUF_SIZE];

static inline void tcg_context_init(TCGContext *s)
{
    memset(s, 0, sizeof(*s));
}

void cpu_gen_init(void)
{
    tcg_context_init(&tcg_ctx); 
}

/* return non zero if the very first instruction is invalid so that
   the virtual CPU can trigger an exception.

   '*gen_code_size_ptr' contains the size of the generated code (host
   code).
*/
int cpu_gen_code(CPUArchState *env, TranslationBlock *tb, int *gen_code_size_ptr)
{
    TCGContext *s = &tcg_ctx;
    int gen_code_size;

    gen_code_size = ARM_gen_code(env, s, tb);
    *gen_code_size_ptr = gen_code_size;

#ifdef DEBUG_DISAS
    if (qemu_loglevel_mask(CPU_LOG_TB_OUT_ASM)) {
        qemu_log("OUT: [size=%d]\n", gen_code_size);
        log_target_disas(env, tb->tc_ptr, gen_code_size,
                env->thumb | (env->bswap_code << 1));
        qemu_log("\n");
        qemu_log_flush();
    }
#endif

    return 0;
}

int cpu_restore_state(TranslationBlock *tb,
                      CPUArchState *env, uintptr_t searched_pc)
{
    /* dummy */
    abort();
    return 0;
}

