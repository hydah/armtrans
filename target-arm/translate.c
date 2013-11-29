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

#define ENABLE_ARCH_4T    arm_feature(env, ARM_FEATURE_V4T)
#define ENABLE_ARCH_5     arm_feature(env, ARM_FEATURE_V5)
/* currently all emulated v5 cores are also v5TE, so don't bother */
#define ENABLE_ARCH_5TE   arm_feature(env, ARM_FEATURE_V5)
#define ENABLE_ARCH_5J    0
#define ENABLE_ARCH_6     arm_feature(env, ARM_FEATURE_V6)
#define ENABLE_ARCH_6K   arm_feature(env, ARM_FEATURE_V6K)
#define ENABLE_ARCH_6T2   arm_feature(env, ARM_FEATURE_THUMB2)
#define ENABLE_ARCH_7     arm_feature(env, ARM_FEATURE_V7)

#define ARCH(x) do { if (!ENABLE_ARCH_##x) goto illegal_op; } while(0)

/* internal defines */
typedef struct DisasContext {
    target_ulong pc;
    int is_jmp;
    /* Nonzero if this instruction has been conditionally skipped.  */
    int condjmp;
    /* The label that will be jumped to when the instruction is skipped.  */
    int condlabel;
    /* Thumb-2 conditional execution bits.  */
    int condexec_mask;
    int condexec_cond;
    struct TranslationBlock *tb;
    int singlestep_enabled;
    int thumb;
    int bswap_code;
#if !defined(CONFIG_USER_ONLY)
    int user;
#endif
    int vfp_enabled;
    int vec_len;
    int vec_stride;
} DisasContext;


#if defined(CONFIG_USER_ONLY)
#define IS_USER(s) 1
#else
#define IS_USER(s) (s->user)
#endif

/* These instructions trap after executing, so defer them until after the
   conditional execution state has been updated.  */
#define DISAS_WFI 4
#define DISAS_SWI 5



static const char *regnames[] =
    { "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
      "r8", "r9", "r10", "r11", "r12", "r13", "r14", "pc" };

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

int cc_prolog_init(CPUARMState *env, TCGContext *s);

static void cemit_push(TCGContext *s, Field rd)
{
    Inst inst;

    inst = COND(COND_AL) | INST_DATATRAN_IMD | TRAN_ST | INDEX_PRE | ADDR_WB | 
           ADDR_DEC | (rd << RD_POS) | (REG_SP << RN_POS) | 4;

    code_emit32(s->code_ptr, inst);
}

static void cemit_pop(TCGContext *s, Field rd)
{
    Inst inst;

    inst = COND(COND_AL) | INST_DATATRAN_IMD | TRAN_LD | INDEX_POST |
           ADDR_INC | (rd << RD_POS) | (REG_SP << RN_POS) | 4;

    code_emit32(s->code_ptr, inst);
}

static void cemit_datatran_imm(TCGContext *s, Field st_ld, Field pre_post,
                               Field wb, Field dir, Field rd, Field rn, Field off)
{
    Inst inst;

    inst = COND(COND_AL) | INST_DATATRAN_IMD | st_ld | pre_post | wb | 
           dir | (rd << RD_POS) | (rn << RN_POS) | BITS(off, 0, TRAN_IMM_BITS);

    code_emit32(s->code_ptr, inst);
}

static void cemit_datapro_imm(TCGContext *s, Field op, Field rd, 
                              Field rn, Field ror, Field imm)
{
    Inst inst;

    inst = COND(COND_AL) | INST_DATAPRO_IMD | (op << OP_POS) | (rd << RD_POS) |
           (rn << RN_POS) | (ror << ROR_POS) | BITS(imm, 0, PRO_IMM_BITS);

    code_emit32(s->code_ptr, inst);
}

static void cemit_datapro_reg(TCGContext *s, Field op, Field rd, 
                              Field rn, Field rm, Field r_type, Field rc)
{
    Inst inst;

    inst = COND(COND_AL) | INST_DATAPRO_REG | (op << OP_POS) | (rd << RD_POS) |
           (rn << RN_POS) | (r_type << RTYPE_POS) | (rc << RC_POS) | rm;

    code_emit32(s->code_ptr, inst);
}

static void cemit_branch(TCGContext *s, Field cond, Inst *pc, Inst *target)
{
    Inst inst;
    int off;

    off = target - (pc + 2);
    
    if((off < BR_BOUND) && (off >= -BR_BOUND)) {
        inst = COND(cond)| INST_BRANCH | BITS(off, 0, BR_OFF_BITS);
        code_emit32(s->code_ptr, inst);
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

static void cemit_mov_i32(TCGContext *s, Field Rd, uint32_t imm32)
{
    uint8_t imm8, pos;
    int i;

    imm8 = BITS(imm32, 0, 8);

    cemit_datapro_imm(s, OP_MOV, Rd, 0, 0, imm8);

    for(i = 1; i < 4; i++) {
        pos = 8 * i;
        imm8 = BITS(imm32, pos, 8);
        if(imm8 != 0x0) {
            cemit_datapro_imm(s, OP_ORR, Rd, 0, (32 - pos) / 2, imm8);
        }
    }
}

static void cemit_pc_rel(TCGContext *s, decode_t *ds)
{
    Field Rt;
    Inst inst;

    inst = *ds->pc;
    Rt = find_free_reg(ds);

    cemit_push(s, Rt);
    cemit_mov_i32(s, Rt, (uint32_t)(ds->pc + 2));
    inst = CLR_BITS(inst, RN_POS, REG_BITS) | (Rt << RN_POS);
    code_emit32(s->code_ptr, inst);
    cemit_pop(s, Rt);
}

static void cemit_exit_tb(TCGContext *s, Inst *target, TranslationBlock *tb)
{
    Inst *patch_pc;

    /* push r0 */
    cemit_push(s, REG_R0);
    /* add r0, pc, off */
    patch_pc = s->code_ptr;
    cemit_datapro_imm(s, OP_ADD, REG_R0, REG_PC, 0, NEED_PATCH);
    /* back to translator */
    cemit_branch(s, COND_AL, s->code_ptr, tb_ret_addr);

    modify_pro_imm(patch_pc, s->code_ptr);
    /* store (tb, next_pc) in code cache */
    code_emit32(s->code_ptr, (Inst)tb);
    code_emit32(s->code_ptr, (Inst)target);
}

static void cemit_exit_tb_ind(TCGContext *s, Field Rt, TranslationBlock *tb)
{
    Inst *patch_pc1, *patch_pc2;

    /* str Rt, [pc, off] */
    patch_pc1 = s->code_ptr;
    cemit_datatran_imm(s, TRAN_ST, INDEX_PRE, ADDR_NO_WB, ADDR_INC, 
                      Rt, REG_PC, NEED_PATCH);

    if(Rt != REG_R0) {
        /* pop Rt */
        cemit_pop(s, Rt);
        /* push r0 */
        cemit_push(s, REG_R0);
    }

    /* add r0, pc, off */
    patch_pc2 = s->code_ptr;
    cemit_datapro_imm(s, OP_ADD, REG_R0, REG_PC, 0, NEED_PATCH);

    /* back to translator */
    cemit_branch(s, COND_AL, s->code_ptr, tb_ret_addr);

    modify_pro_imm(patch_pc2, s->code_ptr);
    /* store tb in code cache */
    code_emit32(s->code_ptr, (Inst)tb);
    modify_tran_imm(patch_pc1, s->code_ptr);
    s->code_ptr += 4;
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

bool emit_null(TCGContext *s, decode_t *ds) 
{
    AT_ERR("emit_null line:%d, func:%s\n", __LINE__, __func__);
    abort();
    return true;
}

bool emit_exception(TCGContext *s, decode_t *ds)
{
    AT_DBG("exception pc = %p\n", ds->pc);
    return true;
}

bool emit_branch(TCGContext *s, decode_t *ds)
{
    Inst *target, *patch_pc;

    if(ds->L == 0x1) {
        /* mov [pc + 4] to lr  */
        cemit_mov_i32(s, REG_LR, (uint32_t)(ds->pc + 1));
    }
    
    if(ds->cond != COND_AL) {
        patch_pc = s->code_ptr;
        /* b exit_stub_2  #need patch */
        cemit_branch(s, NEG_COND(ds->cond), s->code_ptr, s->code_ptr);

        /* exit_stub_1: */
        target = ds->pc + 2 + ds->off; /* In ARM, pc=pc+8 after fetch inst */
        cemit_exit_tb(s, target, s->cur_tb);

        /* exit_stub_2: */
        modify_br_off(patch_pc, s->code_ptr);
        target = ds->pc + 1;
        cemit_exit_tb(s, target, s->cur_tb);
    } else {
        target = ds->pc + 2 + ds->off;
        cemit_exit_tb(s, target, s->cur_tb);
    }

    return true;
}

bool emit_normal(TCGContext *s, decode_t *ds) 
{
    if(ds->Rn == REG_PC) {
        cemit_pc_rel(s, ds);
    } else {
        /* copy inst */
        *(uint32_t *)s->code_ptr = *ds->pc;
        s->code_ptr++;
    }

    return false;
}

bool emit_br_ind(TCGContext *s, decode_t *ds)
{
    Inst inst, *target, *patch_pc;
    Field Rt;
   
    AT_DBG("br_ind: pc = %p\n", ds->pc);
    if(ds->cond != COND_AL) {
        patch_pc = s->code_ptr;
        cemit_branch(s, NEG_COND(ds->cond), s->code_ptr, s->code_ptr);

        target = ds->pc + 1;
        cemit_exit_tb(s, target, s->cur_tb);

        modify_br_off(patch_pc, s->code_ptr);
    }

    inst = *(ds->pc);
    Rt = find_free_reg(ds);

    /* push Rt */
    cemit_push(s, Rt);

    /* ind type: data_op/ld -> pc 
       change dest_reg from pc to Rt */
    if(ds->op != (INST_DATATRAN_BLK >> FUNC_POS)) {
        if(ds->Rn == REG_PC) {
            cemit_mov_i32(s, Rt, (uint32_t)(ds->pc + 2));
            inst = CLR_BITS(inst, RN_POS, REG_BITS) | (Rt << RN_POS);
        }
        inst = CLR_BITS(inst, RD_POS, REG_BITS) | (Rt << RD_POS);
        code_emit32(s->code_ptr, inst);
    } else {
        if(ds->Rn == REG_PC) {
            AT_ERR("multi load pc-rel\n");
        }
        inst = CLR_BITS(inst, REG_PC, 1); /* clear bit-15 */
        code_emit32(s->code_ptr, inst);
        inst = CLR_BITS(inst, 0, REG_NUM) | (0x1 << Rt);
        code_emit32(s->code_ptr, inst);
    }

    cemit_exit_tb_ind(s, Rt, s->cur_tb);

    return true;
}

static void cemit_cpsr_all(TCGContext *s, Field sr_rs_all, Field rd)
{
    Inst inst;
    inst = COND(COND_AL) | INST_DATAPRO_REG | sr_rs_all | rd;
    code_emit32(s->code_ptr, inst);
}

static void ld_st_gregs(TCGContext *s, Field st_ld, Field rd, Field rn, Field off)
{
    Field pre_post = INDEX_PRE;
    Field wb = ADDR_NO_WB;
    Field dir = ADDR_INC;
    Field i = 0;
    for (i = rd; i <= 14; i++) {
        cemit_datatran_imm(s, st_ld, pre_post, wb, dir, i, rn, off);
    }
}

static void ld_st_cpsr(TCGContext *s, Field rs_sr, Field st_ld,  Field rd, Field rn, Field off)
{
    Field pre_post = INDEX_PRE;
    Field wb = ADDR_NO_WB;
    Field dir = ADDR_INC;
    if (rs_sr == CPSR_STOR_ALL)
    {
    	// mrs
        cemit_cpsr_all(s, rs_sr, rd << 12);
        cemit_datatran_imm(s, st_ld, pre_post, wb, dir, rd, rn, off);
    }
    else
    {
    	// msr
        cemit_datatran_imm(s, st_ld, pre_post, wb, dir, rd, rn, off);
        cemit_cpsr_all(s, rs_sr, rd); 
    }
}

static void preserve_host_state(CPUARMState *env, TCGContext *s)
{
    uint32_t off;
    /*store some data in arm_code_cache + 50 */
    fprintf(stderr, "env->tpc is %x\n", env->tpc);

    /* bakeup armtrans's context */
    /* str REG_R1，(tpc) */
    off = (env->tpc - s->code_ptr - 2) * 4;
    cemit_datatran_imm(s, TRAN_ST, INDEX_PRE, ADDR_NO_WB, ADDR_INC, REG_R1, REG_PC, off);
    /* stmdb sp!, {r4-r12, lr} */
    code_emit32(s->code_ptr, (COND_AL << 28) | 0x092d5ff0);
    /* str REG_SP, (sp_tmp) */
    off = (env->sp_tmp - s->code_ptr - 2) * 4;
    cemit_datatran_imm(s, TRAN_ST, INDEX_PRE, ADDR_NO_WB, ADDR_INC, REG_SP, REG_PC, off);

}

static void restore_host_state(CPUARMState *env, TCGContext *s)
{
    uint32_t off;
    /* ldr REG_SP, (sp_tmp) */
    off = (env->sp_tmp - (uint32_t *)s->code_ptr - 2) * 4;
    cemit_datatran_imm(s, TRAN_ST, INDEX_PRE, ADDR_NO_WB, ADDR_INC, REG_SP, REG_PC, off);

    /* ldmdb sp!, {r4-r12, pc} */
    code_emit32(s->code_ptr, (COND_AL << 28) | 0x08bd9ff0);

}

static void preserve_guest_state(CPUARMState *env, TCGContext *s)
{
    uint32_t off;
    /* preserve cc's environment. Note r0 is stored on [sp] now. */
    off = (env->regs - s->code_ptr - 2) * 4;
    ld_st_gregs(s, TRAN_ST, REG_R0, REG_PC, off);
    
    cemit_pop(s, REG_R1); 	/* use r1 to mov the [sp] to context[r0] */
    off = (env->regs - (uint32_t *)s->code_ptr - 2) * 4;
    cemit_datatran_imm(s, TRAN_ST, INDEX_PRE, ADDR_NO_WB, ADDR_INC, REG_R1, REG_PC, off);
    
    off = (env->cpsr - (uint32_t *)s->code_ptr - 2) * 4;
    ld_st_cpsr(s, CPSR_STOR_ALL, TRAN_ST, REG_R1, REG_PC, off);

}

static void restore_guest_state(CPUARMState *env, TCGContext *s)
{
    uint32_t off;
    /* restore cc's context! */
    off = (env->cpsr - (uint32_t *)s->code_ptr - 2) * 4;
    ld_st_cpsr(s, CPSR_RTOS_ALL, TRAN_LD, REG_R0, REG_PC, off);

    off = (env->regs - (uint32_t *)s->code_ptr - 2) * 4;
    ld_st_gregs(s, TRAN_LD, REG_R0, REG_PC, off);

}

int cc_prolog_init(CPUARMState *env, TCGContext *s)
{
    Field off;
    int size;

    s->code_buf = (uint32_t *)code_gen_prologue;
    s->code_ptr = s->code_buf;

    env->tpc = (uint32_t *)code_gen_prologue + 50;
    env->sp_tmp = env->tpc + 1;
    env->regs = env->sp_tmp + 1;
    env->cpsr = env->regs + 15; 

    AT_DBG("prologue init\n");
    /* prologue */
    preserve_host_state(env, s);
    restore_guest_state(env, s);
    
    /* jump to code cache */
    off = (env->tpc - (uint32_t *)s->code_ptr - 2) * 4;
    cemit_datatran_imm(s, TRAN_LD, INDEX_PRE, ADDR_NO_WB, ADDR_INC, REG_PC, REG_PC, off);
    tb_ret_addr = s->code_ptr;

    /* epilogue */
    preserve_guest_state(env, s);
    restore_host_state(env, s);

    flush_icache_range((tcg_target_ulong)s->code_buf,
                       (tcg_target_ulong)s->code_ptr);

    /* preserve the space for context */
    s->code_ptr = s->code_buf + (67 + 1);
    size = s->code_ptr - s->code_buf;
    size *= 4;
    if (qemu_loglevel_mask(CPU_LOG_TB_IN_ASM)) {
        qemu_log("ARM-prologue/epilogue: [size=%d]\n", size);
        log_target_disas(env, (uint32_t)s->code_buf, size, 0);
        qemu_log("\n");
        qemu_log_flush();
    }
    return 0;
}


int arm_gen_code(CPUArchState *env, TCGContext *s, TranslationBlock *tb);
int arm_gen_code(CPUArchState *env, TCGContext *s, TranslationBlock *tb)
{
    Inst *cc_ptr_start, *pc;
    decode_t ds1, *ds = &ds1;
    size_t cc_size;
    size_t src_size;
    bool end;

    s->cur_tb = tb;
    s->code_ptr = (uint32_t *)tb->tc_ptr;
    pc = (Inst *)tb->pc;
    cc_ptr_start = s->code_ptr;

    do {
    	disas_insn(pc, ds);
        end = ds->fun(env, ds);
        pc++;
    } while(end != true);

    cc_size = (s->code_ptr - cc_ptr_start) * 4;
    src_size = (pc - (Inst *)tb->pc) * 4;
    

#ifdef DEBUG_DISAS
    if (qemu_loglevel_mask(CPU_LOG_TB_IN_ASM)) {
        qemu_log("OUT: [size=%d]\n", src_size);
        log_disas((Inst *)tb->pc, src_size);
        qemu_log("\n");
        qemu_log_flush();
    }
#endif
    return cc_size;
}

void cpu_dump_state(CPUARMState *env, FILE *f, fprintf_function cpu_fprintf,
                    int flags)
{
}
