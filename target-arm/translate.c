/*
 *  ARM translation
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *  Copyright (c) 2005-2007 CodeSourcery
 *  Copyright (c) 2007 OpenedHand, Ltd.
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

#include "cpu.h"
#include "disas.h"
//#include "tcg-op.h"
#include "qemu-log.h"
#include "translate-all.h"

//#include "helper.h"
//#define GEN_HELPER 1
//#include "helper.h"
#include "decode.h"
#include "emit.h"
#include "translate.h"

int cc_prolog_init(CPUARMState *env, TCGContext *s);
int arm_gen_code(CPUArchState *env, TCGContext *s, TranslationBlock *tb);

int cc_prolog_init(CPUARMState *env, TCGContext *s)
{
    arm_prolog_init(env, s);
    //thumb_prolog_init(env, s);
    return 0;
}

int ARM_gen_code(CPUArchState *env, TCGContext *s, TranslationBlock *tb)
{
    uint8_t *cc_ptr_start, *pc;
    decode_t ds1, *ds = &ds1;
    size_t cc_size;
    size_t src_size;
    bool retcode;
    uint8_t *temp;

    s->cur_tb = tb;
    s->code_ptr = (uint32_t *)tb->tc_ptr;
    fprintf(stderr, "s->code_ptr is %x.[%d@%s]\n", s->code_ptr, __LINE__, __FUNCTION__);
    fprintf(stderr, "tb->pc is %x.[%d@%s]\n", tb->pc, __LINE__, __FUNCTION__);
    pc = (Inst *)tb->pc;
    temp = (uint8_t *)tb->pc;
    cc_ptr_start = s->code_ptr;
    fprintf(stderr, "tb->pc is %x.[%d@%s]\n", *temp++, __LINE__, __FUNCTION__);
    fprintf(stderr, "tb->pc is %x.[%d@%s]\n", *temp++, __LINE__, __FUNCTION__);
    fprintf(stderr, "tb->pc is %x.[%d@%s]\n", *temp++, __LINE__, __FUNCTION__);
    fprintf(stderr, "tb->pc is %x.[%d@%s]\n", *temp++, __LINE__, __FUNCTION__);

    ds->pc = (uint8_t *)tb->pc;
    ds->bswap_code = 0;

    do {
        /*should decide current cpu state: thumb or arm*/
        if (env->thumb) {
            disas_thumb_inst(env, s, ds);
        } else {
            disas_arm_inst(env, s, ds);
        }

        retcode = ds->func(env, s, ds);
        ds->pc = ds->pc + (4 >> env->thumb);
    } while(retcode != true);

    cc_size = s->code_ptr - cc_ptr_start;
    src_size = ds->pc - (uint8_t *)tb->pc;
    

#ifdef DEBUG_DISAS
    if (qemu_loglevel_mask(CPU_LOG_TB_IN_ASM)) {
        qemu_log("----------------\n");
        qemu_log("IN: %s [size=%d]\n", lookup_symbol(tb->pc), src_size);
        log_target_disas(env, tb->pc, src_size,
                env->thumb | (ds->bswap_code << 1));
        qemu_log("\n");
    }
#endif
    return cc_size;
}

void cpu_dump_state(CPUARMState *env, FILE *f, fprintf_function cpu_fprintf,
                    int flags)
{
}
