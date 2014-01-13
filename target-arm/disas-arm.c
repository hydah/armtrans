#include "translate-all.h"
#include "translate.h"
#include "decode.h"
#include "emit.h"

static const char *regnames[] =
    { "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
      "r8", "r9", "r10", "r11", "r12", "r13", "r14", "pc" };

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
        CPSR_RTOS_ALL = 0x12ff000,
};

static uint32_t find_free_reg(uint32_t reg_list)
{
    int r;
    
    for (r = 0; r < 13; r++) {
        if (BITS(reg_list, r, 1) == 0x1)
            continue;
        return r;
    }

    AT_DBG("Cannot find free reg\n");
    abort();
}

static void cemit_push(TCGContext *s, Field rd)
{
    uint32_t inst;

    inst = COND(COND_AL) | INST_DATATRAN_IMD | TRAN_ST | INDEX_PRE | ADDR_WB | 
           ADDR_DEC | (rd << RD_POS) | (REG_SP << RN_POS) | 4;

    code_emit32(s->code_ptr, inst);
}

static void cemit_pop(TCGContext *s, Field rd)
{
    uint32_t inst;

    inst = COND(COND_AL) | INST_DATATRAN_IMD | TRAN_LD | INDEX_POST |
           ADDR_INC | (rd << RD_POS) | (REG_SP << RN_POS) | 4;

    code_emit32(s->code_ptr, inst);
}

static void cemit_datatran_imm(TCGContext *s, Field st_ld, Field pre_post,
                               Field wb, Field dir, Field rd, Field rn, Field off)
{
    uint32_t inst;

    inst = COND(COND_AL) | INST_DATATRAN_IMD | st_ld | pre_post | wb | 
           dir | (rd << RD_POS) | (rn << RN_POS) | BITS(off, 0, TRAN_IMM_BITS);

    code_emit32(s->code_ptr, inst);
}

static void cemit_datapro_imm(TCGContext *s, Field op, Field rd, 
                              Field rn, Field ror, Field imm)
{
    uint32_t inst;

    inst = COND(COND_AL) | INST_DATAPRO_IMD | (op << OP_POS) | (rd << RD_POS) |
           (rn << RN_POS) | (ror << ROR_POS) | BITS(imm, 0, PRO_IMM_BITS);

    code_emit32(s->code_ptr, inst);
}

static void cemit_datapro_reg(TCGContext *s, Field op, Field rd, 
                              Field rn, Field rm, Field r_type, Field rc)
{
    uint32_t inst;

    inst = COND(COND_AL) | INST_DATAPRO_REG | (op << OP_POS) | (rd << RD_POS) |
           (rn << RN_POS) | (r_type << RTYPE_POS) | (rc << RC_POS) | rm;

    code_emit32(s->code_ptr, inst);
}

static void cemit_branch(TCGContext *s, Field cond, Inst *pc, Inst *target)
{
    uint32_t inst;
    int off;

    off = target - (pc + 8);
    
    if((off < BR_BOUND) && (off >= -BR_BOUND)) {
        inst = COND(cond)| INST_BRANCH | BITS(off, 0, BR_OFF_BITS);
        code_emit32(s->code_ptr, inst);
    } else {
        AT_ERR("offset exceeds bound\n");
    }
}

static void modify_br_off(Inst *pc, Inst *target)
{
    uint32_t inst;
    int off;

    inst = *(uint32_t *)pc;
    inst = CLR_BITS(inst, 0, BR_OFF_BITS);

    off = target - (pc + 8);

    if((off < BR_BOUND) && (off >= -BR_BOUND)) {
        inst |= BITS(off, 2, BR_OFF_BITS);
        *(uint32_t *)pc = inst;
    } else {
        AT_ERR("offset exceeds bound\n");
    }

}

static void modify_tran_imm(Inst *pc, Inst *target)
{
    uint32_t inst;
    int imm;

    inst = *(uint32_t *)pc;
    inst = CLR_BITS(inst, 0, TRAN_IMM_BITS);

    imm = target - (pc + 8);

    if(imm < 0) {
        inst &= (~ADDR_INC);
        imm = -imm;
    } else {
        inst |= ADDR_INC;
    }

    if(imm < (1 << TRAN_IMM_BITS)) {
        inst |= BITS(imm, 0, TRAN_IMM_BITS);
        *(uint32_t *)pc = inst;
    } else {
        AT_ERR("offset exceeds bound\n");
    }
}

static void modify_pro_imm(Inst *pc, Inst *target)
{
    uint32_t inst;
    int imm;

    inst = *(uint32_t *)pc;
    inst = CLR_BITS(inst, 0, PRO_IMM_BITS);

    imm = target - (pc + 8);

    if(imm < 0) {
        inst = CLR_BITS(inst, OP_POS, OP_BITS);
        inst |= (OP_SUB << OP_POS);
        imm = -imm;
    }

    if(imm < (1 << PRO_IMM_BITS)) {
        inst |= BITS(imm, 0, PRO_IMM_BITS);
        *(uint32_t *)pc = inst;
    } else {
        AT_ERR("offset exceeds bound\n");
    }
}

static void cemit_mov_imm32(TCGContext *s, Field Rd, uint32_t imm32)
{
    uint8_t imm8, pos;
    int i;

    imm8 = BITS(imm32, 0, 8);

    cemit_datapro_imm(s, OP_MOV, Rd, 0, 0, imm8);

    for(i = 1; i < 4; i++) {
        pos = 8 * i;
        imm8 = BITS(imm32, pos, 8);
        if(imm8 != 0x0) {
            cemit_datapro_imm(s, OP_ORR, Rd, Rd, (32 - pos) / 2, imm8);
        }
    }
}

static void cemit_pc_rel(TCGContext *s, decode_t *ds)
{
    Field Rt;
    uint32_t inst;

    inst = *ds->pc;
    Rt = find_free_reg(ds->reg_list);

    cemit_push(s, Rt);
    cemit_mov_imm32(s, Rt, (uint32_t)(ds->pc + 2));
    inst = CLR_BITS(inst, RN_POS, REG_BITS) | (Rt << RN_POS);
    code_emit32(s->code_ptr, inst);
    cemit_pop(s, Rt);
}

static bool cemit_normal(TCGContext *s, decode_t *ds) 
{

    uint32_t inst;
    int Rm_rep, Rn_rep, Rs_rep;

    inst = ds->inst;
    /* assume that there are 3 source registers at most.
     * any src_reg may be REG_PC
     */

    if (ds->rs_num >= 1 && ds->Rm == REG_PC) {
        Rm_rep = find_free_reg(ds->reg_list);
        ds->reg_list |= 1 << Rm_rep;
        cemit_push(s, Rm_rep);
        cemit_mov_imm32(s, Rm_rep, (uint32_t)ds->pc + 8);
        inst = inst & ~(0xf << ds->Rm_pos);
        inst |= (Rm_rep << ds->Rm_pos);
    }
    if (ds->rs_num >= 2 && ds->Rn == REG_PC) {
        Rn_rep = find_free_reg(ds->reg_list);
        ds->reg_list |= 1 << Rn_rep;
        cemit_push(s, Rn_rep);
        cemit_mov_imm32(s, Rn_rep, (uint32_t)ds->pc + 8);
        inst = inst & ~(0xf << ds->Rn_pos);
        inst |= (Rn_rep << ds->Rn_pos);
    }
    if (ds->rs_num >= 3 && ds->Rs == REG_PC) {
        Rs_rep = find_free_reg(ds->reg_list);
        ds->reg_list |= 1 << Rs_rep;
        cemit_push(s, Rs_rep);
        cemit_mov_imm32(s, Rs_rep, (uint32_t)ds->pc + 8);
        inst = inst & ~(0xf << ds->Rs_pos);
        inst |= (Rs_rep << ds->Rs_pos);
    }

    /* copy inst */
    fprintf(stderr, "s->code_ptr is %x.[%d@%s]\n", s->code_ptr, __LINE__, __FUNCTION__);
    code_emit32(s->code_ptr, inst);

    if (ds->rs_num >= 3 && ds->Rs == REG_PC) {
        cemit_pop(s, Rs_rep);
    }
    if (ds->rs_num >= 2 && ds->Rn == REG_PC) {
        cemit_pop(s, Rn_rep);
    }
    if (ds->rs_num >= 1 && ds->Rm == REG_PC) {
        cemit_pop(s, Rm_rep);
    }

    return false;
}

static void cemit_exit_tb(TCGContext *s, Inst *target)
{
    Inst *patch_pc;
    struct TranslationBlock *tb;
    
    tb = s->cur_tb;

    /* push r0 */
    cemit_push(s, REG_R0);
    /* add r0, pc, off */
    patch_pc = s->code_ptr;
    cemit_datapro_imm(s, OP_ADD, REG_R0, REG_PC, 0, 0);
    /* back to translator */
    cemit_push(s, REG_R1);
    cemit_mov_imm32(s, REG_R1, s->tb_ret_addr);
    cemit_datapro_reg(s, OP_MOV, REG_PC, 0, REG_R1, 0, 0);

    modify_pro_imm(patch_pc, s->code_ptr);
    /* store (tb, next_pc) in code cache */
    code_emit32(s->code_ptr, (uint32_t)target);
    code_emit32(s->code_ptr, (uint32_t)tb);
}

static int cemit_exit_tb_ind(TCGContext *s, decode_t *ds, uint32_t Rt)
{
    struct TranslationBlock *tb;
    uint8_t *patch_dest, *patch_r0, *patch_r1, *patch_stub;
    uint8_t *patch_pc1, *patch_pc2;
    int stub_addr;

    tb = s->cur_tb;

    if (tb->type == DATA_TRA || tb->type == DATA_PRO) {
        /* str Rt, [temp_pos] */
        patch_pc1 = s->code_ptr;
        cemit_datatran_imm(s, TRAN_ST, INDEX_PRE, ADDR_NO_WB, ADDR_INC, 
                      Rt, REG_PC, s->code_ptr);

        /* write pc --> write Rt */ 
        cemit_normal(s, ds);

        /* str Rt, [dest_pos] */
        patch_dest = s->code_ptr;
        cemit_datatran_imm(s, TRAN_ST, INDEX_PRE, ADDR_NO_WB, ADDR_INC, 
                      Rt, REG_PC, s->code_ptr);

        /* ldr Rt, [temp_pos] */
        patch_pc2 = s->code_ptr;
        cemit_datatran_imm(s, TRAN_LD, INDEX_PRE, ADDR_NO_WB, ADDR_INC, 
                      Rt, REG_PC, s->code_ptr);
    } else {
        /* str Rt, [dest_pos] */
        patch_dest = s->code_ptr;
        cemit_datatran_imm(s, TRAN_ST, INDEX_PRE, ADDR_NO_WB, ADDR_INC, 
                Rt, REG_PC, s->code_ptr);
    }


    /* push r0 */
    cemit_push(s, REG_R0);
    /* push r1 */
    cemit_push(s, REG_R1);

#if 0
    /* str r0, [r0_pos] */
    patch_r0 = s->code_ptr;
    cemit_datatran_imm(s, TRAN_ST, INDEX_PRE, ADDR_NO_WB, ADDR_INC, 
            REG_R0, REG_PC, s->code_ptr);

    /* str r1, [r1_pos] */
    patch_r1 = s->code_ptr;
    cemit_datatran_imm(s, TRAN_ST, INDEX_PRE, ADDR_NO_WB, ADDR_INC, 
            REG_R1, REG_PC, s->code_ptr);
#endif

    /* r0 = start address of the stub 
     *  == add r0, pc, off
     */
    patch_stub = s->code_ptr;
    cemit_datapro_imm(s, OP_ADD, REG_R0, REG_PC, 0, 0);

    /* back to translator */
    cemit_mov_imm32(s, REG_R1, s->tb_ret_addr);
    cemit_datapro_reg(s, OP_MOV, REG_PC, 0, REG_R1, 0, 0);

    modify_pro_imm(patch_stub, s->code_ptr);
    /* stub: */
    stub_addr = s->code_ptr;
    /* dest */
    modify_tran_imm(patch_dest, s->code_ptr);
    s->code_ptr += 4;
    /* store tb in code cache */
    code_emit32(s->code_ptr, (uint32_t)tb);
#if 0
    /* r0 */
    modify_tran_imm(patch_r0, s->code_ptr);
    s->code_ptr += 4;
    /* r1 or temp */
    modify_tran_imm(patch_r1, s->code_ptr);
#endif
    if (tb->type == DATA_TRA || tb->type == DATA_PRO) {
        modify_tran_imm(patch_pc1, s->code_ptr);
        modify_tran_imm(patch_pc2, s->code_ptr);
        s->code_ptr += 4;
    }

    return stub_addr;
}

static void cemit_exit_tb_msr(TCGContext *s, decode_t *ds, uint32_t Rt)
{
    fprintf(stderr, "never occur!\n");
    abort();
}

bool emit_null(TCGContext *s, decode_t *ds) 
{
    AT_ERR("emit_null line:%d, func:%s\n", __LINE__, __func__);
    abort();
    return true;
}

#if 0
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
        cemit_mov_imm32(s, REG_LR, (uint32_t)(ds->pc + 1));
    }
    
    if(ds->cond != COND_AL) {
        patch_pc = s->code_ptr;
        /* b exit_stub_2  #need patch */
        cemit_branch(s, NEG_COND(ds->cond), s->code_ptr, s->code_ptr);

        /* exit_stub_1: */
        target = ds->pc + 2 + ds->off; /* In ARM, pc=pc+8 after fetch inst */
        cemit_exit_tb(s, target);

        /* exit_stub_2: */
        modify_br_off(patch_pc, s->code_ptr);
        target = ds->pc + 1;
        cemit_exit_tb(s, target);
    } else {
        target = ds->pc + 2 + ds->off;
        cemit_exit_tb(s, target);
    }

    return true;
}

bool emit_br_ind(TCGContext *s, decode_t *ds)
{
    uint32_t inst, *target, *patch_pc;
    Field Rt;
   
    AT_DBG("br_ind: pc = %p\n", ds->pc);
    if(ds->cond != COND_AL) {
        patch_pc = (uint32_t *)s->code_ptr;
        cemit_branch(s, NEG_COND(ds->cond), s->code_ptr, s->code_ptr);

        target = ds->pc + 1;
        cemit_exit_tb(s, target);

        modify_br_off(patch_pc, s->code_ptr);
    }

    inst = *(ds->pc);
    Rt = find_free_reg(ds->reg_list);

    /* push Rt */
    cemit_push(s, Rt);

    /* ind type: data_op/ld -> pc 
       change dest_reg from pc to Rt */
    if(ds->op != (INST_DATATRAN_BLK >> FUNC_POS)) {
        if(ds->Rn == REG_PC) {
            cemit_mov_imm32(s, Rt, (uint32_t)(ds->pc + 2));
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

    cemit_exit_tb_ind(s, Rt);

    return true;
}
#endif


static bool write_pc(TCGContext *s, decode_t *ds, uint32_t rd_pos, uint32_t reg_free)
{
    uint32_t inst;
    uint32_t *patch_stub1, *patch_stub2;
    uint32_t target;
    int stub_addr;

    inst = ds->inst;
    inst = inst & ~(0xf << rd_pos) | (reg_free << rd_pos);
    ds->reg_list = ds->reg_list | (1 << reg_free);
    ds->inst = inst;

    if (ds->cond != COND_AL) {
        patch_stub1 = s->code_ptr;
        /* (cond)b patch_stub1 */
        cemit_branch(s, ds->cond, s->code_ptr, s->code_ptr); 

        target = ds->pc + 4;
        patch_stub2 = s->code_ptr;
        /* b patch_stub2 */
        cemit_branch(s, COND_AL, s->code_ptr, s->code_ptr);
        /* patch_stub2: */
        modify_br_off(patch_stub2, s->code_ptr);
        cemit_exit_tb(s, target);

        /* patch_stub1: */
        modify_br_off(patch_stub1, s->code_ptr);
    }

    stub_addr = cemit_exit_tb_ind(s, ds, reg_free);
    if (s->cur_tb->type == DATA_TRA) 
        s->cur_tb->change_state_addr = stub_addr;

    return true;
}

static bool try_emit_normal(TCGContext *s, decode_t *ds)
{
    uint32_t reg_free;

    reg_free = find_free_reg(ds->reg_list);

    if (ds->rd_num >= 1 && ds->Rd == REG_PC) {
        return  write_pc(s, ds, ds->Rd_pos, reg_free);
    } else if (ds->rd_num >=2 && ds->Rd2 == REG_PC) {
        return  write_pc(s, ds, ds->Rd2_pos, reg_free);
    } else {
        return cemit_normal(s, ds);
    }
    
    return false;
}

static bool xlate_branch_reg(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    /* there are 3 instructions in total.
     * bx rm
     * bxj rm 
     * blx rm
     */
    uint32_t inst;
    uint32_t pc;
    struct TranslationBlock *tb;
    uint32_t target;
    uint32_t *patch_stub1, *patch_stub2;
    
    inst = ds->inst;
    pc = ds->pc;
    tb = s->cur_tb;
    tb->type = BRANCH;
    ds->cond = BITS(inst, 28, 4);

    ds->Rm = BITS(inst, 0, 4);
    tb->may_change_state = 1;
    tb->exit_tb_nopush = 1;

    if (ds->cond != COND_AL) {
        patch_stub1 = s->code_ptr;
        cemit_branch(s, ds->cond, s->code_ptr, s->code_ptr); 

        target = ds->pc + 4;
        patch_stub2 = s->code_ptr;
        cemit_branch(s, COND_AL, s->code_ptr, s->code_ptr);
        /* patch_stub2: */
        modify_br_off(patch_stub2, s->code_ptr);
        cemit_exit_tb(s, target);

        /* patch_stub1: */
        modify_br_off(patch_stub1, s->code_ptr);
    }

    switch (BITS(inst, 4, 4)) {
        case 0x1:
            /* bx rm */
            tb->change_state_addr = cemit_exit_tb_ind(s, ds, ds->Rm);
            break;
        case 0x2:
            /* bxj == bx */
            tb->change_state_addr = cemit_exit_tb_ind(s, ds, ds->Rm);
            break;
        case 0x3:
            /* blx rm */
            cemit_mov_imm32(s, REG_LR, pc + 4);
            tb->change_state_addr = cemit_exit_tb_ind(s, ds, ds->Rm);
        default:
            abort();
            break;
    }

    return true;
}

static bool xlate_branch_imm(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    /* there are 3 instructions in total:
     * blx imm
     * b imm
     * bl imm
     */
    uint32_t inst;
    uint32_t target, target2;
    uint32_t pc;
    uint32_t *patch_stub1, *patch_stub2;
    struct TranslationBlock *tb;
    int offset;

    inst = ds->inst;
    ds->cond = BITS(inst, 28, 4);
    pc = ds->pc;
    offset = BITS(inst, 0, 24);
    offset = (offset << 8) >> 8;
    offset = offset << 2;

    tb = s->cur_tb;
    tb->type = BRANCH;

    if (ds->cond == 0xf) {
        /*blx imm*/
        offset = offset | ((inst >> 23) & 2) | 0x1;
        target = pc + 8 + offset;

        tb->may_change_state = 1;
        cemit_mov_imm32(s, REG_LR, pc + 4);
        cemit_exit_tb(s, target);// must change the cpu state

    } else {
        target = pc + 8 + offset;

        if (ds->cond != COND_AL) {
            patch_stub1 = s->code_ptr;
            /* (cond)b patch_stub1 */
            cemit_branch(s, ds->cond, s->code_ptr, s->code_ptr); 

            target2 = ds->pc + 4;
            patch_stub2 = s->code_ptr;
            /* b patch_stub2 */
            cemit_branch(s, COND_AL, s->code_ptr, s->code_ptr);
            /* patch_stub2: */
            modify_br_off(patch_stub2, s->code_ptr);
            cemit_exit_tb(s, target2);

            /* patch_stub1: */
            modify_br_off(patch_stub1, s->code_ptr);
        }

        if (BITS(inst, 24, 1) == 0x1) {
            /*bl imm*/
            cemit_mov_imm32(s, REG_LR, pc + 4);
            cemit_exit_tb(s, target);
        } else {
            /*b imm*/
            cemit_exit_tb(s, target);
        }
    }

    return true;
}

static bool xlate_data_pro_reg(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    /* the type of instructions is:
     * clz
     * qadd/qsub/qdadd/qdsub
     * smul
     * multiply
     * data_pro_imm_shift
     * data_pro_reg_shift
     */

    uint32_t inst;
    uint32_t Rd, Rm, Rn, Rs;
    uint32_t rd_pos, rn_pos;
    uint32_t reg_free;

    s->cur_tb->type = DATA_PRO;

    inst = ds->inst;
    
    if (inst & 0x0ff000f0 == 0x01600010) {
        /* clz rd, rm */
        ds->Rd = BITS(inst, 12, 4);    
        ds->Rd_pos = 12;
        ds->Rm = BITS(inst, 0, 4);
        ds->Rm_pos = 0;
        ds->rd_num = 1;
        ds->rs_num = 1;
        ds->reg_list = (1 << ds->Rd) | (1 << ds->Rm);
        reg_free = find_free_reg(ds->reg_list);
    } else if (inst & 0x0f9000f0 == 0x01000050) {
        /* qadd qsub qdadd qdsub */
        ds->Rd = BITS(inst, 12, 4);    
        ds->Rd_pos = 12;
        ds->Rm = BITS(inst, 0, 4);
        ds->Rm_pos = 0;
        ds->Rn = BITS(inst, 16, 4);    
        ds->Rn_pos = 16;
        ds->rd_num = 1;
        ds->rs_num = 2;
        ds->reg_list = (1 << ds->Rd) | (1 << ds->Rm) | (1 << ds->Rn);
        reg_free = find_free_reg(ds->reg_list);
    } else if (inst & 0x0ff00090 == 0x01000080) {
        /* smul */
        ds->Rn = BITS(inst, 12, 4);    
        ds->Rn_pos = 12;
        ds->Rd = BITS(inst, 16, 4);    
        ds->Rd_pos = 16;
        ds->Rm = BITS(inst, 0, 4);
        ds->Rm_pos = 0;
        ds->Rs = BITS(inst, 8, 4);
        ds->Rs_pos = 0;
        ds->rd_num = 1;
        ds->rs_num = 3;
        ds->reg_list = (1 << ds->Rd) | (1 << ds->Rm) | (1 << ds->Rn) | (1 << ds->Rs);
        reg_free = find_free_reg(ds->reg_list);
    } else if (inst & 0x0f0000f0 == 0x00000090) {
        /* multiply */
        /* Fixme: Rn may be REG_PC. */
        ds->Rn = BITS(inst, 12, 4);    
        ds->Rn_pos = 12;
        Rd = BITS(inst, 16, 4);    
        ds->Rd_pos = 16;
        ds->Rm = BITS(inst, 0, 4);
        ds->Rm_pos = 0;
        ds->Rs = BITS(inst, 8, 4);
        ds->Rs_pos = 8;
        ds->rd_num = 1;
        ds->rs_num = 3;
        ds->reg_list = (1 << ds->Rd) | (1 << ds->Rm) | (1 << ds->Rn) | (1 << ds->Rs);
        reg_free = find_free_reg(ds->reg_list);
    } else if (BITS(inst, 4, 1) == 0x0) {
        /*data_pro_imm_shift*/
        ds->Rd = BITS(inst, 12, 4);
        ds->Rd_pos = 12;
        ds->Rm = BITS(inst, 0, 4);
        ds->Rm_pos = 0;
        ds->Rn = BITS(inst, 16, 4);
        ds->Rn_pos = 16;
        ds->rd_num = 1;
        ds->rs_num = 2;
        ds->reg_list = (1 << ds->Rd) | (1 << ds->Rm) | (1 << ds->Rn);
        reg_free = find_free_reg(ds->reg_list);
    } else if (BITS(inst, 4, 0) == 0x1) {
        /*data_pro_reg_shift*/
        ds->Rd = BITS(inst, 12, 4);
        ds->Rd_pos = 12;
        ds->Rm = BITS(inst, 0, 4);
        ds->Rn = BITS(inst, 16, 4);
        ds->Rs = BITS(inst, 8, 4);
        ds->Rm_pos = 0;
        ds->Rn_pos = 16;
        ds->Rs_pos = 8;
        ds->rd_num = 1;
        ds->rs_num = 3;
        ds->reg_list = (1 << ds->Rd) | (1 << ds->Rm) | (1 << ds->Rn) | (1 << ds->Rs);
        reg_free = find_free_reg(ds->reg_list);
    }

    return try_emit_normal(s, ds);
}

static bool xlate_data_pro_imm(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    /* the type of correlated instructions is:
     * general data_pro_imm
     */

    uint32_t inst;
    uint32_t Rd, Rn;
    uint32_t rd_pos, reg_free;

    s->cur_tb->type = DATA_PRO;
    inst = ds->inst;
    ds->Rd = BITS(inst, 12, 4);
    ds->Rd_pos = 12;
    ds->Rm = BITS(inst, 16, 4);
    ds->Rm_pos = 16;
    ds->rd_num = 1;
    ds->rs_num = 1;
    ds->reg_list = (1 << ds->Rd) | (1 << ds->Rm);

    return try_emit_normal(s, ds);
}

static bool xlate_data_tra_reg(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    /* the type of correlated instructions is:
     * extra ld/st
     * ld/st
     * muti ld/st
     */

    uint32_t inst;
    uint32_t index;
    uint32_t reg_free;

    s->cur_tb->type = DATA_TRA;
    

    inst = ds->inst;
    index = ds->index;
    ds->Rd = BITS(inst, 12, 4);
    ds->Rd_pos = 12;
    ds->Rn = BITS(inst, 16, 4);
    ds->Rm = BITS(inst, 0, 4);
    ds->Rn_pos = 16;
    ds->Rm_pos = 0;
    ds->rd_num = 1;
    ds->rs_num = 2;
    ds->reg_list = (1 << ds->Rd) | (1 << ds->Rm) | (1 << ds->Rn);
    ds->Rl = BITS(inst, 0, 15);

    if (BITS(inst, 20, 1) == 0x0) {
        ds->rd_num = 0;
        ds->Rs = ds->Rd;
        ds->Rs_pos = 12;
        ds->rs_num = 3;
    }

    if(index == 0x0) {
        /* extra ld/st */
        if ((inst & 0xc0) == 0xc0 && BITS(inst, 20, 1) == 0x1) {
            /* ld */
            return try_emit_normal(s, ds);
        } else if ((inst & 0xf0) == 0xf0) {
            /* ld double */
            if (ds->Rd == REG_LR) {
                AT_DBG(" ld double. Rd cannot be lr\n");
                abort();
            } else {
                return cemit_normal(s, ds);
            }
        } else if (BITS(inst, 20, 1) == 0x1) {
            /* ld */
            return try_emit_normal(s, ds);
        } else {
            /* st */
            return cemit_normal(s, ds);
        }
    } else if (index == 0x3) {
        /* ld/st reg */
        if (BITS(inst, 20, 1) == 0x1) {
            /* ld */
            s->cur_tb->may_change_state = 1;
        }
        return try_emit_normal(s, ds);
    } else if (index == 0x4) {
        /* muti ld/st */
        /* ldm/stm/push/pop */
        ds->Rm = BITS(inst, 16, 4);
        ds->Rm_pos = 16;
        ds->reg_list = BITS(inst, 0, 16) | (1 << ds->Rm);
        ds->rd_num = 0; 
        ds->rs_num = 1; 
        if (inst & (1 << 20)) {
            /* ldm/pop */
            if (inst & (1 << 15)) {
                /* write pc */
                uint32_t *patch_stub1, *patch_stub2;
                uint32_t target;
                s->cur_tb->may_change_state = 1;

                if (ds->cond != COND_AL) {
                    patch_stub1 = s->code_ptr;
                    /* (cond)b patch_stub1 */
                    cemit_branch(s, ds->cond, s->code_ptr, NEED_PATCH); 

                    target = ds->pc + 4;
                    patch_stub2 = s->code_ptr;
                    /* b patch_stub2 */
                    cemit_branch(s, COND_AL, s->code_ptr, NEED_PATCH);
                    /* patch_stub2: */
                    modify_br_off(patch_stub2, s->code_ptr);
                    cemit_exit_tb(s, target);

                    /* patch_stub1: */
                    modify_br_off(patch_stub1, s->code_ptr);
                }

                ds->inst = inst & ~(1 << 15);
                cemit_normal(s, ds);
                reg_free = find_free_reg((1 << ds->Rm));
                ds->inst = (ds->inst & ~((1 << 15) - 1) | (1 << reg_free));
                s->cur_tb->change_state_addr = cemit_exit_tb_ind(s, ds, reg_free);
                return true;
            } else {
                return cemit_normal(s, ds); 
            }    

        } else {
            /* stm/push */
            return cemit_normal(s, ds); 
        }    

    }

}

static bool xlate_data_tra_imm(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    /* the type of correlated instructions is:
     * general ld/st imm offset
     */

    uint32_t inst;
    uint32_t index;
    uint32_t reg_free, rd_pos;

    s->cur_tb->type = DATA_TRA;
    inst = ds->inst;

    ds->Rd = BITS(inst, 12, 4);
    ds->Rm = BITS(inst, 16, 4);
    ds->Rd_pos = 12;
    ds->Rm_pos = 16;
    ds->rs_num = 1;
    ds->rd_num = 1;
    ds->reg_list = (1 << ds->Rd) | (1 << ds->Rm);
    
    if (BITS(inst, 20, 1) == 0x1) {
        /* ld */
        s->cur_tb->may_change_state = 1;
        return try_emit_normal(s, ds);
    } else {
        /* st */
        ds->Rn = ds->Rd;
        ds->Rn_pos = 12;
        ds->rs_num = 2;
        return cemit_normal(s, ds);
    }
    return false;
}

static bool xlate_state_tra_reg(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    /* the type of correlated instructions is:
     * msr reg
     * mrs reg
     */

    uint32_t inst;
    uint32_t Rd, Rm;
    uint32_t rd_pos, reg_free;
    struct TranslationBlock *tb;

    inst = ds->inst;
    Rd = BITS(inst, 12, 4);
    Rm = BITS(inst, 0, 4);
    rd_pos = 12;
    reg_free = REG_R0;
    tb = s->cur_tb;
    

    if (BITS(inst, 21, 1) == 0x0) {
        /*mrs rd, cpsr*/
        if (Rd == REG_PC) {
            write_pc(s, ds, rd_pos, reg_free);
        } else {
            cemit_normal(s, ds);
        }
    } else {
        /*msr cpsr, rm*/
        tb->exit_tb_nopush = 1;
        cemit_exit_tb_msr(s, ds, Rm);
    }
}
static bool xlate_state_tra_imm(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    /* the type of correlated instructions is:
     * msr cpsr imm
     */
    uint32_t reg_free;
    uint32_t inst;

    inst = ds->inst;
    reg_free = REG_R0;

    cemit_push(s, reg_free);
    /* mov regfree, imm */
    code_emit32(s->code_ptr, (inst & 0xff0fffff | (0xa << 20) | (reg_free << 12)));
    cemit_exit_tb_msr(s, ds, reg_free);
}

static bool xlate_exception(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    /* copy inst */
    fprintf(stderr, "s->code_ptr is %x.[%d@%s]\n", s->code_ptr, __LINE__, __FUNCTION__);
    code_emit32(s->code_ptr, ds->inst);
    return false;
}

static bool xlate_coprocessor(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    /* copy inst */
    fprintf(stderr, "s->code_ptr is %x.[%d@%s]\n", s->code_ptr, __LINE__, __FUNCTION__);
    code_emit32(s->code_ptr, ds->inst);

    return false;
}

static bool xlate_nop(CPUARMState *env, TCGContext  *s, decode_t *ds)
{
    return false;
}

void disas_arm_inst(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    unsigned int cond, inst, val, op1, i, shift, rm, rs, rn, rd, sh;

    inst = arm_ldl_code(env, ds->pc, ds->bswap_code);
    ds->inst = inst;
    ds->cond = BITS(inst, 28, 4);
    ds->index = BITS(inst, 25, 3);
    ds->op = BITS(inst, 21, 4);

    /* M variants do not implement ARM mode.  */
    if (IS_M(env))
        goto illegal_op;
    if (ds->cond == 0xf){
        /* In ARMv3 and v4 the NV condition is UNPREDICTABLE; we
         * choose to UNDEF. In ARMv5 and above the space is used
         * for miscellaneous unconditional instructions.
         */
        switch (ds->index) {
            case 0x0:
                if ((inst & 0x0ff10020) == 0x01000000) {
                    /* cps (privileged) */
                    if (IS_USER(s))
                        return;
                    else
                        abort();
                } else if ((inst & 0x0ffffdff) == 0x01010000) { 
                    ARCH(6);
                    /* setend */
                    if (((inst >> 9) & 1) != ds->bswap_code) { 
                        /* Dynamic endianness switching not implemented. */
                        abort();
                    }
                    return;
                }
                return;
            case 0x1:
                abort();
                return;
            case 0x2:
            case 0x3:
                /* pld */
                if (((inst & 0x0f30f000) == 0x0510f000) ||
                        ((inst & 0x0f30f010) == 0x0710f000)) {
                    if ((inst & (1 << 22)) == 0) {
                        /* PLDW; v7MP */
                        if (!arm_feature(env, ARM_FEATURE_V7MP)) {
                            goto illegal_op;
                        }
                    }
                    /* Otherwise PLD; v5TE+ */
                    ARCH(5TE);
                    ds->func = xlate_nop; 
                }

                return;
            case 0x4:
                if ((inst & 0x0e5fffe0) == 0x084d0500) { 
                    /* srs */ 
                    if (IS_USER(s))
                        goto illegal_op;
                    ARCH(6);
                } else if ((inst & 0x0e50ffe0) == 0x08100a00) {
                    /* rfe */
                    if (IS_USER(s))
                        goto illegal_op;
                    ARCH(6);
                }
                return;
            case 0x5:
                if ((inst & 0x0e000000) == 0x0a000000) {
                    /* blx imm */
                    ds->func = xlate_branch_imm;
                } else {
                    abort();
                }
                return;
            case 0x6:
                if ((inst & 0x0fe00000) == 0x0c400000) {
                    /* Coprocessor double register transfer.  */
                    ARCH(5TE);
                }
                return;
            case 0x7:
                if ((inst & 0x0f000010) == 0x0e000010) {
                    /* Additional coprocessor register transfer.  */
                } else {
                    /* Undefined instruction */
                    abort();
                }
                return;
            default :
                return;
        }
    }

    if (ds->cond != 0xe) {
        /* if not always execute, we generate a conditional jump to
           next instruction */
        //ds->condjmp = 1;
    }
    switch (ds->index) {
        case 0x0:
            /*data_pro; miscellaneous inst; multiplies; extra load|store */
            if (BITS(inst, 23, 2) == 0x2 && BITS(inst, 20, 1) == 0x0) {
                /*miscellaneous inst*/
                switch (BITS(inst, 4, 4)) {
                    case 0x0:
                        if (BITS(inst, 21, 1) == 0x0) {
                            /*mrs rd, cpsr*/
                            ds->func = xlate_state_tra_reg;
                        } else {
                            /*msr cpsr, rd*/
                            ds->func = xlate_state_tra_reg;
                        }
                        break;
                    case 0x1:
                        if (BITS(inst, 21, 2) == 0x1) {
                            /*bx rm*/
                            ds->func = xlate_branch_reg;
                        }else if(BITS(inst, 21, 2) == 0x3) {
                            /*clz rm*/
                            ds->func = xlate_data_pro_reg;
                        } else {
                            abort();
                        }
                        break;
                    case 0x2:
                        if (BITS(inst, 21, 2) == 0x1) {
                            /*bxj rm*/
                            ds->func = xlate_branch_reg;
                        } else {
                            abort();
                        }
                        break;
                    case 0x3:
                        if (BITS(inst, 21, 2) == 0x1) {
                            /*blx rm*/
                            ds->func = xlate_branch_reg;
                        } else {
                            abort();
                        }
                        break;
                    case 0x5:
                        switch (BITS(inst, 21, 2)) {
                            case 0x0:
                                /*qadd rd, rn, rm*/
                            case 0x1:
                                /*qsub rd, rn, rm*/
                            case 0x2:
                                /*qdadd rd, rn, rm*/
                            case 0x3:
                                /*qdsub rd, rn, rm*/
                                ds->func = xlate_data_pro_reg;
                            default:
                                break;
                        }
                    case 0x7:
                        if (BITS(inst, 21, 2) == 0x1) {
                            /*bkpt imm*/
                            ds->func = xlate_exception;
                        } else {
                            abort();
                        }
                        break;
                    case 0x8:
                    case 0xa:
                    case 0xc:
                    case 0xe:
                        switch (BITS(inst, 21, 2)) {
                                case 0x0:
                                    /*SMLA<x><y>*/
                                    break;
                                case 0x1:
                                    if (BITS(inst, 5, 1) == 0x0) {
                                       /*SMLAW<y>*/
                                    } else {
                                    /*SMULW<y>*/
                                    }
                                case 0x2:
                                    /*SMLAL<x><y>*/
                                case 0x3:
                                    /*SMUL<x><y>*/
                                    ds->func = xlate_data_pro_reg;

                                default:
                                    abort();
                        }
                        break;
                    default:
                        abort();
                } /*end of switch*/
            } else if (BITS(inst, 24, 1) == 0x0 && BITS(inst, 4, 4) == 0x9) {
                /*multiply instructions*/
                ds->func = xlate_data_pro_reg;
            } else if (BITS(inst, 7, 1) == 0x1 && BITS(inst, 4, 1) == 0x1) {
                /*extra load/store inst*/
                ds->func = xlate_data_tra_reg;
            } else if (BITS(inst, 4, 1) == 0x0) {
                /*data_pro_imm_shift*/
                ds->func = xlate_data_pro_reg;
            } else if (BITS(inst, 4, 0) == 0x1) {
                /*data_pro_reg_shift*/
                ds->func = xlate_data_pro_reg;
            } else {
                abort();
            }
            
            break;
        case 0x1:
            if (BITS(inst, 23, 2) == 0x2 && BITS(inst, 20, 2) == 0x2) {
                /*msr cpsr, imm */
                ds->func = xlate_state_tra_imm;
            } else if(BITS(inst, 23, 2) == 0x2 && BITS(inst, 20, 2) == 0x0) {
                abort();
            } else {
                /*data_pro_imm*/
                ds->func = xlate_data_pro_imm;
            }

            break;

        case 0x2:
            /*ld/st imm*/
            ds->func = xlate_data_tra_imm;
            break;    
        case 0x3:
            if (BITS(inst, 4, 1) == 0x0) {
                /*ld/st reg*/
                ds->func = xlate_data_tra_reg;
            } else {
                /*media inst*/
                /*architecturally undefined*/
            }

            break;
        case 0x4:
            /*ld/st mutiple*/
            ds->func = xlate_data_tra_reg;
            break;
        case 0x5:
            /*b/bl*/
            ds->func = xlate_branch_imm;
            break;
        case 0x6:
            /*coprocessor*/
            ds->func = xlate_coprocessor;
            break;
        case 0x7:
            if (BITS(inst, 24, 1) == 0x1) {
                /*swi*/
                ds->func = xlate_exception;
            } else if (BITS(inst, 24, 1) == 0x0 && BITS(inst, 4, 1) == 0x0) {
                /*coprocessor data_pro*/
            } else if (BITS(inst, 24, 1) == 0x0 && BITS(inst, 4, 1) == 0x1) {
                /*coprocessor reg_tra*/
            } else {
                abort();
            }
            break;
        default :
            break;
    }

    return 0;
illegal_op:
    abort();
}


static void cemit_cpsr_all(TCGContext *s, Field sr_rs_all, Field rd)
{
    uint32_t inst;
    inst = COND(COND_AL) | INST_DATAPRO_REG | sr_rs_all | rd;
    code_emit32(s->code_ptr, inst);
}

static void ld_st_gregs(TCGContext *s, Field st_ld, Field rd, Field rn, Field off)
{
    Field pre_post = INDEX_PRE;
    Field wb = ADDR_NO_WB;
    Field dir = ADDR_INC;
    Field i = 0;
    for (i = rd; i < 15; i++) {
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
    off = (env->tpc - (uint32_t *)s->code_ptr - 2) * 4;
    cemit_datatran_imm(s, TRAN_ST, INDEX_PRE, ADDR_NO_WB, ADDR_INC, REG_R1, REG_PC, off);
    /* stmdb sp!, {r4-r12, lr} */
    code_emit32(s->code_ptr, (COND_AL << 28) | 0x092d5ff0);
    /* str REG_SP, (sp_tmp) */
    off = (env->sp_tmp - (uint32_t *)s->code_ptr - 2) * 4;
    cemit_datatran_imm(s, TRAN_ST, INDEX_PRE, ADDR_NO_WB, ADDR_INC, REG_SP, REG_PC, off);

}

static void restore_host_state(CPUARMState *env, TCGContext *s)
{
    uint32_t off;
    /* ldr REG_SP, (sp_tmp) */
    off = (env->sp_tmp - (uint32_t *)s->code_ptr - 2) * 4;
    cemit_datatran_imm(s, TRAN_LD, INDEX_PRE, ADDR_NO_WB, ADDR_INC, REG_SP, REG_PC, off);

    /* ldmdb sp!, {r4-r12, pc} */
    code_emit32(s->code_ptr, (COND_AL << 28) | 0x08bd9ff0);

}

static void preserve_guest_state(CPUARMState *env, TCGContext *s)
{
    uint32_t off;
    /* preserve cc's environment. Note r1, r0 is stored on [sp] now. */
    off = (env->regs - (uint32_t *)s->code_ptr - 2) * 4;
    ld_st_gregs(s, TRAN_ST, REG_R0, REG_PC, off);
    
    cemit_pop(s, REG_R2); 	/* use r2 to mov the [sp](r1) to regs[1] */
    off = (env->regs + 1 - (uint32_t *)s->code_ptr - 2) * 4;
    cemit_datatran_imm(s, TRAN_ST, INDEX_PRE, ADDR_NO_WB, ADDR_INC, REG_R2, REG_PC, off);
    cemit_pop(s, REG_R2); 	/* use r2 to mov the [sp](r0) to regs[0] */
    off = (env->regs - (uint32_t *)s->code_ptr - 2) * 4;
    cemit_datatran_imm(s, TRAN_ST, INDEX_PRE, ADDR_NO_WB, ADDR_INC, REG_R2, REG_PC, off);

    off = (env->regs + 13 - (uint32_t *)s->code_ptr - 2) * 4;
    cemit_datatran_imm(s, TRAN_ST, INDEX_PRE, ADDR_NO_WB, ADDR_INC, REG_SP, REG_PC, off);
    
    off = (env->cpsr - (uint32_t *)s->code_ptr - 2) * 4;
    ld_st_cpsr(s, CPSR_STOR_ALL, TRAN_ST, REG_R1, REG_PC, off);

}

static void restore_guest_state(CPUARMState *env, TCGContext *s)
{
    uint32_t off;
    /* restore cc's context! */
    off = (env->cpsr - (uint32_t *)s->code_ptr - 2) * 4;
    /* important */
    off += 4;
    ld_st_cpsr(s, CPSR_RTOS_ALL, TRAN_LD, REG_R0, REG_PC, off);

    off = (env->regs - (uint32_t *)s->code_ptr - 2) * 4;
    ld_st_gregs(s, TRAN_LD, REG_R0, REG_PC, off);

}

int arm_prolog_init(CPUARMState *env, TCGContext *s)
{
    Field off;
    int size;

    s->code_buf = code_gen_prologue;
    s->code_ptr = s->code_buf;

    env->sp_tmp = (uint32_t *)code_gen_prologue + 50;
    env->regs = env->sp_tmp + 1;
    env->tpc = env->regs + 15;
    env->cpsr = env->tpc + 1; 

    AT_DBG("prologue init\n");
    /* prologue */
    preserve_host_state(env, s);
    restore_guest_state(env, s);
    
    /* jump to code cache */
    off = (env->tpc - (uint32_t *)s->code_ptr - 2) * 4;
    cemit_datatran_imm(s, TRAN_LD, INDEX_PRE, ADDR_NO_WB, ADDR_INC, REG_PC, REG_PC, off);
    s->tb_ret_addr = s->code_ptr;

    /* epilogue */
    preserve_guest_state(env, s);
    restore_host_state(env, s);

    /* preserve the space for context */
    s->code_ptr = s->code_buf + (68 + 1) * 4;
    flush_icache_range((tcg_target_ulong)s->code_buf,
                       (tcg_target_ulong)s->code_ptr);

    size = s->code_ptr - s->code_buf;
    if (qemu_loglevel_mask(CPU_LOG_TB_IN_ASM)) {
        qemu_log("ARM-prologue/epilogue: [size=%d]\n", size);
        log_target_disas(env, (uint32_t)s->code_buf, size, 0);
        qemu_log("\n");
        qemu_log_flush();
    }
    fprintf(stderr, "s->code_ptr is %x\n", s->code_ptr);
    return 0;
}
