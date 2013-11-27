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
#include "tcg.h"
#include "qemu-timer.h"

#include "decode.h"
#include "emit.h"

int cc_prolog_init(CPUArchState *env);
static Inst *tb_ret_addr;

#define INST_BITS	32
#define BR_OFF_BITS	24
#define TRAN_IMM_BITS	12
#define PRO_IMM_BITS	8
#define IMM_ROR_BITS	4
#define BR_BOUND (1 << (BR_OFF_BITS -1))
#define NEG_COND(c) ((c) ^ 0x1)
#define NEED_PATCH	0x5a5a5a5a

enum filed_pos {
    RTYPE_POS = 4,
    RC_POS = 7,
    ROR_POS = 8,
    RD_POS = 12,
    RN_POS = 16,
    OP_POS = 21,
    FUNC_POS = 25,
    COND_POS = 28,
};

enum filed_bits {
    OP_BITS = 4,
    REG_BITS = 4,
};

#define COND(c)	(c << COND_POS)
enum cond_field {
    COND_EQ,
    COND_AL = 0xe,
};


enum inst_func {
    INST_DATAPRO_REG = (0 << FUNC_POS),
    INST_DATAPRO_IMD = (1 << FUNC_POS),
    INST_DATATRAN_IMD = (2 << FUNC_POS),
    INST_DATATRAN_REG = (3 << FUNC_POS),
    INST_DATATRAN_BLK = (4 << FUNC_POS),
    INST_BRANCH = (5 << FUNC_POS),
};

enum inst_filed {
    TRAN_ST = (0 << 20),
    TRAN_LD = (1 << 20),
    INDEX_POST = (0 << 24),
    INDEX_PRE = (1 << 24),
    ADDR_DEC = (0 << 23),
    ADDR_INC = (1 << 23),
    ADDR_NO_WB = (0 << 21),
    ADDR_WB = (1 << 21),
    LDST_BTYE = (1 << 22),
    SET_CPSR = (1 << 20),
};

enum inst_cpsr {
        CPSR_STOR_ALL = 0x10f0000,
        CPSR_RTOS_ALL = 0x129f000,
};

static Inst arm_code_cache[8 * 1024 * 1024];

static void cemit_push(CPUArchState *env, Field rd)
{
    Inst inst;

    inst = COND(COND_AL) | INST_DATATRAN_IMD | TRAN_ST | INDEX_PRE | ADDR_WB | 
           ADDR_DEC | (rd << RD_POS) | (REG_SP << RN_POS) | 4;

    code_emit32(env->cc_ptr, inst);
}

static void cemit_pop(CPUArchState *env, Field rd)
{
    Inst inst;

    inst = COND(COND_AL) | INST_DATATRAN_IMD | TRAN_LD | INDEX_POST |
           ADDR_INC | (rd << RD_POS) | (REG_SP << RN_POS) | 4;

    code_emit32(env->cc_ptr, inst);
}

static void cemit_datatran_imm(CPUArchState *env, Field st_ld, Field pre_post,
                               Field wb, Field dir, Field rd, Field rn, Field off)
{
    Inst inst;

    inst = COND(COND_AL) | INST_DATATRAN_IMD | st_ld | pre_post | wb | 
           dir | (rd << RD_POS) | (rn << RN_POS) | BITS(off, 0, TRAN_IMM_BITS);

    code_emit32(env->cc_ptr, inst);
}

static void cemit_datapro_imm(CPUArchState *env, Field op, Field rd, 
                              Field rn, Field ror, Field imm)
{
    Inst inst;

    inst = COND(COND_AL) | INST_DATAPRO_IMD | (op << OP_POS) | (rd << RD_POS) |
           (rn << RN_POS) | (ror << ROR_POS) | BITS(imm, 0, PRO_IMM_BITS);

    code_emit32(env->cc_ptr, inst);
}

static void cemit_datapro_reg(CPUArchState *env, Field op, Field rd, 
                              Field rn, Field rm, Field r_type, Field rc)
{
    Inst inst;

    inst = COND(COND_AL) | INST_DATAPRO_REG | (op << OP_POS) | (rd << RD_POS) |
           (rn << RN_POS) | (r_type << RTYPE_POS) | (rc << RC_POS) | rm;

    code_emit32(env->cc_ptr, inst);
}

static void cemit_branch(CPUArchState *env, Field cond, Inst *pc, Inst *target)
{
    Inst inst;
    int off;

    off = target - (pc + 2);
    
    if((off < BR_BOUND) && (off >= -BR_BOUND)) {
        inst = COND(cond)| INST_BRANCH | BITS(off, 0, BR_OFF_BITS);
        code_emit32(env->cc_ptr, inst);
    } else {
        AT_ERR("offset exceeds bound\n");
    }
}

static void modify_br_off(Inst *pc, Inst *target)
{
    Inst inst;
    int off;

    inst = *pc;
    inst = CLR_BITS(inst, 0, BR_OFF_BITS);

    off = target - (pc + 2);

    if((off < BR_BOUND) && (off >= -BR_BOUND)) {
        inst |= BITS(off, 0, BR_OFF_BITS);
        *pc = inst;
    } else {
        AT_ERR("offset exceeds bound\n");
    }

}

static void modify_tran_imm(Inst *pc, Inst *target)
{
    Inst inst;
    int imm;

    inst = *pc;
    inst = CLR_BITS(inst, 0, TRAN_IMM_BITS);

    imm = (target - (pc + 2)) << 2;

    if(imm < 0) {
        inst &= (~ADDR_INC);
        imm = -imm;
    } else {
        inst |= ADDR_INC;
    }

    if(imm < (1 << TRAN_IMM_BITS)) {
        inst |= BITS(imm, 0, TRAN_IMM_BITS);
        *pc = inst;
    } else {
        AT_ERR("offset exceeds bound\n");
    }
}

static void modify_pro_imm(Inst *pc, Inst *target)
{
    Inst inst;
    int imm;

    inst = *pc;
    inst = CLR_BITS(inst, 0, PRO_IMM_BITS);

    imm = (target - (pc + 2)) << 2;

    if(imm < 0) {
        inst = CLR_BITS(inst, OP_POS, OP_BITS);
        inst |= (OP_SUB << OP_POS);
        imm = -imm;
    }

    if(imm < (1 << PRO_IMM_BITS)) {
        inst |= BITS(imm, 0, PRO_IMM_BITS);
        *pc = inst;
    } else {
        AT_ERR("offset exceeds bound\n");
    }
}

static Field find_free_reg(decode_t *ds)
{
    Field Rt;
    bool found;
    int i;

    found = false;

    for(i = 0; i < REG_NUM; i++) {
        Rt = i;
        if((ds->Rd != Rt) && (ds->Rm != Rt) && (ds->Rm != Rt)) {
            if(ds->op == (INST_DATATRAN_BLK >> FUNC_POS)) {
                if(BITS(ds->Rl, Rt, 1) != 0x1) {
                    found = true;
                    break;
                }
            } else {
                found = true;
                break;
            }
        }
    }

    if(found == true) {
        if(Rt != REG_R0) AT_DBG("temp reg is not R0\n");
        return Rt;
    } else {
        AT_ERR("can't find a free reg\n");
        abort();
    }
}

static void cemit_mov_i32(CPUArchState *env, Field Rd, uint32_t imm32)
{
    uint8_t imm8, pos;
    int i;

    imm8 = BITS(imm32, 0, 8);

    cemit_datapro_imm(env, OP_MOV, Rd, 0, 0, imm8);

    for(i = 1; i < 4; i++) {
        pos = 8 * i;
        imm8 = BITS(imm32, pos, 8);
        if(imm8 != 0x0) {
            cemit_datapro_imm(env, OP_ORR, Rd, 0, (32 - pos) / 2, imm8);
        }
    }
}

static void cemit_pc_rel(CPUArchState *env, decode_t *ds)
{
    Field Rt;
    Inst inst;

    inst = *ds->pc;
    Rt = find_free_reg(ds);

    cemit_push(env, Rt);
    cemit_mov_i32(env, Rt, (uint32_t)(ds->pc + 2));
    inst = CLR_BITS(inst, RN_POS, REG_BITS) | (Rt << RN_POS);
    code_emit32(env->cc_ptr, inst);
    cemit_pop(env, Rt);
}

static void cemit_exit_tb(CPUArchState *env, Inst *target, TranslationBlock *tb)
{
    Inst *patch_pc;

    /* push r0 */
    cemit_push(env, REG_R0);
    /* add r0, pc, off */
    patch_pc = env->cc_ptr;
    cemit_datapro_imm(env, OP_ADD, REG_R0, REG_PC, 0, NEED_PATCH);
    /* back to translator */
    cemit_branch(env, COND_AL, env->cc_ptr, tb_ret_addr);

    modify_pro_imm(patch_pc, env->cc_ptr);
    /* store (tb, next_pc) in code cache */
    code_emit32(env->cc_ptr, (Inst)tb);
    code_emit32(env->cc_ptr, (Inst)target);
}

static void cemit_exit_tb_ind(CPUArchState *env, Field Rt, TranslationBlock *tb)
{
    Inst *patch_pc1, *patch_pc2;

    /* str Rt, [pc, off] */
    patch_pc1 = env->cc_ptr;
    cemit_datatran_imm(env, TRAN_ST, INDEX_PRE, ADDR_NO_WB, ADDR_INC, 
                      Rt, REG_PC, NEED_PATCH);

    if(Rt != REG_R0) {
        /* pop Rt */
        cemit_pop(env, Rt);
        /* push r0 */
        cemit_push(env, REG_R0);
    }

    /* add r0, pc, off */
    patch_pc2 = env->cc_ptr;
    cemit_datapro_imm(env, OP_ADD, REG_R0, REG_PC, 0, NEED_PATCH);

    /* back to translator */
    cemit_branch(env, COND_AL, env->cc_ptr, tb_ret_addr);

    modify_pro_imm(patch_pc2, env->cc_ptr);
    /* store tb in code cache */
    code_emit32(env->cc_ptr, (Inst)tb);
    modify_tran_imm(patch_pc1, env->cc_ptr);
    env->cc_ptr++;
}

#if 0
static void cemit_exit_tb(CPUArchState *env, Inst *target, TranslationBlock *tb)
{
    Inst *ret;
    Inst *patch_pc;

    /* push r0 */
    cemit_push(env, REG_R0);
    /* ldr r0, [pc, OFF] */
    patch_pc = env->cc_ptr;
    cemit_datatran_imm(env, TRAN_LD, INDEX_PRE, ADDR_NO_WB, ADDR_DEC, 
                      REG_R0, REG_PC, NEED_PATCH);
    /* back to translator */

    modify_tran_imm(patch_pc, env->cc_ptr);

    ret = env->cc_ptr;
    code_emit32(env->cc_ptr, (Inst)ret);
    /* store (tb, next_pc) in code cache */
    code_emit32(env->cc_ptr, (Inst)tb);
    code_emit32(env->cc_ptr, (Inst)target);
}
#endif

bool emit_null(CPUArchState *env, decode_t *ds) 
{
    AT_ERR("emit_null line:%d, func:%s\n", __LINE__, __func__);
    abort();
    return true;
}

bool emit_exception(CPUArchState *env, decode_t *ds)
{
    AT_DBG("exception pc = %p\n", ds->pc);
    return true;
}

bool emit_branch(CPUArchState *env, decode_t *ds)
{
    Inst *target, *patch_pc;

    if(ds->L == 0x1) {
        /* mov [pc + 4] to lr  */
        cemit_mov_i32(env, REG_LR, (uint32_t)(ds->pc + 1));
    }
    
    if(ds->cond != COND_AL) {
        patch_pc = env->cc_ptr;
        /* b exit_stub_2  #need patch */
        cemit_branch(env, NEG_COND(ds->cond), env->cc_ptr, env->cc_ptr);

        /* exit_stub_1: */
        target = ds->pc + 2 + ds->off; /* In ARM, pc=pc+8 after fetch inst */
        cemit_exit_tb(env, target, env->cur_tb);

        /* exit_stub_2: */
        modify_br_off(patch_pc, env->cc_ptr);
        target = ds->pc + 1;
        cemit_exit_tb(env, target, env->cur_tb);
    } else {
        target = ds->pc + 2 + ds->off;
        cemit_exit_tb(env, target, env->cur_tb);
    }

    return true;
}

bool emit_normal(CPUArchState *env, decode_t *ds) 
{
    if(ds->Rn == REG_PC) {
        cemit_pc_rel(env, ds);
    } else {
        /* copy inst */
        *env->cc_ptr++ = *ds->pc;
    }

    return false;
}

bool emit_br_ind(CPUArchState *env, decode_t *ds)
{
    Inst inst, *target, *patch_pc;
    Field Rt;
   
    AT_DBG("br_ind: pc = %p\n", ds->pc);
    if(ds->cond != COND_AL) {
        patch_pc = env->cc_ptr;
        cemit_branch(env, NEG_COND(ds->cond), env->cc_ptr, env->cc_ptr);

        target = ds->pc + 1;
        cemit_exit_tb(env, target, env->cur_tb);

        modify_br_off(patch_pc, env->cc_ptr);
    }

    inst = *(ds->pc);
    Rt = find_free_reg(ds);

    /* push Rt */
    cemit_push(env, Rt);

    /* ind type: data_op/ld -> pc 
       change dest_reg from pc to Rt */
    if(ds->op != (INST_DATATRAN_BLK >> FUNC_POS)) {
        if(ds->Rn == REG_PC) {
            cemit_mov_i32(env, Rt, (uint32_t)(ds->pc + 2));
            inst = CLR_BITS(inst, RN_POS, REG_BITS) | (Rt << RN_POS);
        }
        inst = CLR_BITS(inst, RD_POS, REG_BITS) | (Rt << RD_POS);
        code_emit32(env->cc_ptr, inst);
    } else {
        if(ds->Rn == REG_PC) {
            AT_ERR("multi load pc-rel\n");
        }
        inst = CLR_BITS(inst, REG_PC, 1); /* clear bit-15 */
        code_emit32(env->cc_ptr, inst);
        inst = CLR_BITS(inst, 0, REG_NUM) | (0x1 << Rt);
        code_emit32(env->cc_ptr, inst);
    }

    cemit_exit_tb_ind(env, Rt, env->cur_tb);

    return true;
}

static void cemit_cpsr_all(CPUArchState *env, Field sr_rs_all, Field rd)
{
    Inst inst;
    inst = COND(COND_AL) | INST_DATAPRO_REG | sr_rs_all | rd;
    code_emit32(env->cc_ptr, inst);
}

static void ld_st_gregs(CPUArchState *env, Field st_ld, Field rd, Field rn, Field off)
{
    Field pre_post = INDEX_PRE;
    Field wb = ADDR_NO_WB;
    Field dir = ADDR_INC;
    Field i = 0;
    for (i = rd; i <= 14; i++) {
        cemit_datatran_imm(env, st_ld, pre_post, wb, dir, i, rn, off);
    }
}

static void ld_st_cpsr(CPUArchState *env, Field rs_sr, Field st_ld,  Field rd, Field rn, Field off)
{
    Field pre_post = INDEX_PRE;
    Field wb = ADDR_NO_WB;
    Field dir = ADDR_INC;
    if (rs_sr == CPSR_STOR_ALL)
    {
    	// mrs
        cemit_cpsr_all(env, rs_sr, rd << 12);
        cemit_datatran_imm(env, st_ld, pre_post, wb, dir, rd, rn, off);
    }
    else
    {
    	// msr
        cemit_datatran_imm(env, st_ld, pre_post, wb, dir, rd, rn, off);
        cemit_cpsr_all(env, rs_sr, rd); 
    }
}

int cc_prolog_init(CPUArchState *env)
{
    Field off;
    int size;

    //env->cc_ptr = code_gen_prologue;
    env->cc_ptr = arm_code_cache;
    AT_DBG("prologue init\n");
    
    /* mov r0, r1. FIXME: mov the 2nd parameter to 1st */
    cemit_datapro_reg(env, OP_MOV, REG_R0, 0, REG_R1, 0, 0);

    /* preserve armtrans's environment */
    off = 0x1f8;
    cemit_datatran_imm(env, TRAN_ST, INDEX_PRE, ADDR_NO_WB, ADDR_INC, REG_R0, REG_PC, off);
    ld_st_gregs(env, TRAN_ST, REG_R4, REG_PC, off);
    
    off = 0x1f4;
    ld_st_cpsr(env, CPSR_STOR_ALL, TRAN_ST, REG_R0, REG_PC, off);
    
    /* restore cc's environment! */
    off = 0x230;
    ld_st_cpsr(env, CPSR_RTOS_ALL, TRAN_LD, REG_R0, REG_PC, off);
    off = 0x1ec;
    ld_st_gregs(env, TRAN_LD, REG_R0, REG_PC, off);
    
    /* jump to code cache */
    off = 0x17c;
    cemit_datatran_imm(env, TRAN_LD, INDEX_PRE, ADDR_NO_WB, ADDR_INC, REG_PC, REG_PC, off);
    tb_ret_addr = env->cc_ptr;
    

    /* epilogue */
    /* preserve cx's environment. Note r0 is stored on [sp] now. */
    off = 0x1b0;
    ld_st_gregs(env, TRAN_ST, REG_R1, REG_PC, off);
    
    cemit_pop(env, REG_R1); 	/* use r1 to mov the [sp] to context[r0] */
    off = 0x170;
    cemit_datatran_imm(env, TRAN_ST, INDEX_PRE, ADDR_NO_WB, ADDR_INC, REG_R1, REG_PC, off);
    
    off = 0x1a4;
    ld_st_cpsr(env, CPSR_STOR_ALL, TRAN_ST, REG_R1, REG_PC, off);
    
    /* restore armtrans's environment */
    off = 0x160;
    ld_st_cpsr(env, CPSR_RTOS_ALL, TRAN_LD, REG_R1, REG_PC, off);
    
    off = 0x12c;
    ld_st_gregs(env, TRAN_LD, REG_R4, REG_PC, off);
    
    /* jump back to translator */
    cemit_datapro_reg(env, OP_MOV, REG_PC, 0, REG_LR, 0, 0);

    /* preserve the space for context */
    env->cc_ptr += 0xff;
    size = env->cc_ptr - arm_code_cache;

    if (qemu_loglevel_mask(CPU_LOG_TB_IN_ASM)) {
        qemu_log("ARM-prologue/epilogue: [size=%d]\n", size);
        log_target_disas(env, (uint32_t)arm_code_cache, size, 0);
        qemu_log("\n");
        qemu_log_flush();
    }

    return 0;
}

static int arm_gen_code(CPUArchState *env, TranslationBlock *tb)
{
    Inst *cc_ptr_start, *pc;
    decode_t ds1, *ds = &ds1;
    size_t size;
    bool end;

    env->cur_tb = tb;
    pc = (Inst *)tb->pc;
    cc_ptr_start = env->cc_ptr;

    do {
    	do_decode(pc, ds);
        end = ds->fun(env, ds);
        pc++;
    } while(end != true);

    size = (env->cc_ptr - cc_ptr_start);

#ifdef DEBUG_DISAS
    if (qemu_loglevel_mask(CPU_LOG_TB_OUT_ASM)) {
        qemu_log("ARM: [size=%d]\n", size);
        log_target_disas(env, (uint32_t)cc_ptr_start, size, 0);
        qemu_log("\n");
        qemu_log_flush();
    }
#endif
 
    return 0;
}

/* code generation context */
TCGContext tcg_ctx;

target_ulong gen_opc_pc[OPC_BUF_SIZE];
uint16_t gen_opc_icount[OPC_BUF_SIZE];
uint8_t gen_opc_instr_start[OPC_BUF_SIZE];

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
    uint8_t *gen_code_buf;
    int gen_code_size;

    tcg_func_start(s);

    gen_intermediate_code(env, tb);

    //arm_gen_code(env, tb);

    /* generate machine code */
    gen_code_buf = tb->tc_ptr;
    tb->tb_next_offset[0] = 0xffff;
    tb->tb_next_offset[1] = 0xffff;
    s->tb_next_offset = tb->tb_next_offset;
    s->tb_jmp_offset = tb->tb_jmp_offset;
    s->tb_next = NULL;

    gen_code_size = tcg_gen_code(s, gen_code_buf);
    *gen_code_size_ptr = gen_code_size;

#ifdef DEBUG_DISAS
    if (qemu_loglevel_mask(CPU_LOG_TB_OUT_ASM)) {
        qemu_log("OUT: [size=%d]\n", *gen_code_size_ptr);
        log_disas(tb->tc_ptr, *gen_code_size_ptr);
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

