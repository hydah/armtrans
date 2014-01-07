#include "translate-all.h"
#include "decode.h"
#include "emit.h"
#include "translate.h"

static uint8_t *thumb_tb_ret_addr;

static uint32_t find_free_reg(uint32_t reg_list)
{
    int r;
    
    for (r = 0; r < 7; r++) {
        if (BITS(reg_list, r, 1) == 0x1)
            continue;
        return r;
    }

    AT_DBG("Cannot find free reg\n");
    abort();
}


static int cemit_thumb2_datatra_imm(TCGContext *s, uint32_t ld_st, uint32_t Rt, uint32_t Rn, uint32_t imm)
{
    uint32_t inst;
    inst = 0xf8c00000;

    if (Rn == REG_PC) {
        abort();
    } else {
        inst = inst | (ld_st << 20) | (Rn << 16) | (Rt << 12) | (BITS(imm, 0, 12));
    }
    *s->code_ptr++ = ((inst >> 16) & 0xff);
    *s->code_ptr++ = ((inst >> 24) & 0xff);
    *s->code_ptr++ = (inst & 0xff);
    *s->code_ptr++ = ((inst >> 8) & 0xff);
        
    return 0;
}
static int modify_thumb2_datatra_imm(TCGContext *s, uint8_t *pc_start, uint8_t *pc_end)
{
    return 0;
}
static int cemit_thumb_datatra_imm(TCGContext *s, uint32_t ld_st, uint32_t Rn, uint32_t Rt, uint32_t imm)
{
    uint32_t inst;
    inst = 0x6000 | ld_st | (BITS(imm, 2, 5) << 6) | ((Rn & 0x7) << 3) | (Rt & 0x7);

    *s->code_ptr++ = inst & 0xff;
    *s->code_ptr++ = (inst >> 8) & 0xff;

    return 0;
}

/* complete */
static void cemit_thumb_push(TCGContext *s, uint32_t reg)
{
    uint32_t inst;
    uint32_t reg_list;

    inst = 0xb400;
    if (reg == 14) {
        reg_list = 1 << 8;
    } else if (reg < 8) {
        reg_list = 1 << reg;
    } else {
        abort();
    }

    inst = inst | reg_list;
    *s->code_ptr++ = inst & 0xff;
    *s->code_ptr++ = (inst >> 8) & 0xff;
}

/* complete */
static void cemit_thumb_pop(TCGContext *s, uint32_t reg)
{
    uint32_t inst;
    uint32_t reg_list;

    inst = 0xbc00;
    if (reg == 15) {
        reg_list = 1 << 8;
    } else if (reg < 8) {
        reg_list = 1 << reg;
    } else {
        abort();
    }

    inst = inst | reg_list;
    *s->code_ptr++ = inst & 0xff;
    *s->code_ptr++ = (inst >> 8) & 0xff;
}

static int cemit_thumb_mov_special(TCGContext *s, uint32_t rd, uint32_t rm)
{
    uint32_t inst;

    inst = 0x4600 | (rm << 3) | BITS(rd, 0, 3) | (BITS(rd, 3, 1) << 7);
    *s->code_ptr++ = inst & 0xff;
    *s->code_ptr++ = (inst >> 8) & 0xff;

    return 0;
}

static int cemit_thumb_add_to_pc(TCGContext *s, uint32_t reg, uint8_t *pc, uint8_t *target)
{
    int offset;
    uint32_t inst;

    pc = (uint32_t)pc & 0xfffffffc;
    offset = target - (pc + 4);

    if (offset < 0x8f && offset > -0x8f) {
        inst = 0xa000 | (reg << 8) | BITS(offset, 2, 8);
        *s->code_ptr++ = inst & 0xff;
        *s->code_ptr++ = (inst >> 8) & 0xff;
    } else {
        abort();
    }

    return 0;
}

static int modify_thumb_addtopc_off(uint8_t *pc_start, uint8_t *pc_end)
{
    int offset;
    uint32_t inst;
    uint32_t *pc_ptr;

    pc_ptr = (uint32_t *)pc_start;
    /* assume that the arch use little endian 
     * only change the low 16bits
     * the upper 16bits belong to other instruction
     * */
    inst = *pc_ptr;
    pc_start = (uint32_t)pc_start & 0xfffffffc;
    offset = pc_end - (pc_start + 4);

    if (offset < ((1 << 7) - 1) && offset > -((1 << 7) - 1)) {
        inst = inst & 0xffffff00;
        inst = inst | BITS(offset, 2, 8);
        *pc_ptr = inst;
    } else {
        abort();
    }

    return 0;
}


static void cemit_store_pc_off(TCGContext *s, uint8_t **patch, uint32_t Rt, uint32_t imm)
{
    uint32_t reg_free;

    reg_free = find_free_reg(1 << Rt);
    cemit_thumb_push(s, reg_free);
    *patch = s->code_ptr;
    cemit_thumb_add_to_pc(s, reg_free, s->code_ptr, imm);
    cemit_thumb2_datatra_imm(s, 0, Rt, reg_free, 0);
    cemit_thumb_pop(s, reg_free);
    return 0;
}

static void cemit_load_pc_off(TCGContext *s, uint8_t **patch, uint32_t Rt, uint32_t imm)
{
    uint32_t inst;
    
    *patch = s->code_ptr;
    inst = 0x4800 | (Rt << 8) | BITS(imm, 2, 8);
    *s->code_ptr++ = inst & 0xff;
    *s->code_ptr++ = (inst >> 8) & 0xff;
}

/* complete */
static int cemit_thumb_mov_imm32(TCGContext *s, uint32_t reg, uint32_t imm)
{
    /* need to be implemented later */
    uint32_t inst;

    /* movw reg, [imm_low16] */
    inst = 0xf2400000;
    inst = inst | (reg << 8) | BITS(imm, 0, 8) | (BITS(imm, 8, 3) << 12) 
                | (BITS(imm, 11, 1) << 26) | (BITS(imm, 12, 4) << 16);
    *s->code_ptr++ = ((inst >> 16) & 0xff);
    *s->code_ptr++ = ((inst >> 24) & 0xff);
    *s->code_ptr++ = (inst & 0xff);
    *s->code_ptr++ = ((inst >> 8) & 0xff);
    
    /* movt reg, [imm_high16] */
    inst = 0xf2c00000;
    inst = inst | (reg << 8) | BITS(imm, 16, 8) | (BITS(imm, 24, 3) << 12) 
                | (BITS(imm, 27, 1) << 26) | (BITS(imm, 28, 4) << 16);
    *s->code_ptr++ = ((inst >> 16) & 0xff);
    *s->code_ptr++ = ((inst >> 24) & 0xff);
    *s->code_ptr++ = (inst & 0xff);
    *s->code_ptr++ = ((inst >> 8) & 0xff);

    return 0;
}

static void cemit_thumb_bx_reg(TCGContext *s, uint32_t reg)
{
    uint32_t inst;
    inst = 0x4700;
    inst = inst | (BITS(reg, 0, 4) << 3);
    *s->code_ptr++ = inst & 0xff;
    *s->code_ptr++ = (inst >> 8) & 0xff;
}

static void cemit_thumb_br_cond(TCGContext *s, uint32_t cond, uint8_t *pc, uint8_t *target)
{
    uint32_t inst;
    int offset;

    offset = target - (pc + 4);

    if (offset < 0x8f && offset > -0x8f) {
        inst = 0xd000 | (cond << 8) | BITS(offset, 0, 8);
        *s->code_ptr++ = inst & 0xff;
        *s->code_ptr++ = (inst >> 8) & 0xff;
    } else {
        abort();
    }
}

static int cemit_thumb_br_uncond(TCGContext *s, uint8_t *pc, uint8_t *target)
{
    uint32_t inst;
    int offset;

    offset = target - (pc + 4);

    if (offset < ((1 << 10) - 1) && offset > -((1 << 10) - 1)) {
        inst = 0xe000 | BITS(offset, 0, 11);
        *s->code_ptr++ = inst & 0xff;
        *s->code_ptr++ = (inst >> 8) & 0xff;
    } else {
        abort();
    }
}

static int modify_thumb_br_uncond_off(TCGContext *s, uint8_t *pc_start, uint8_t *pc_end)
{
    int offset;
    uint32_t inst;
    uint32_t *pc_ptr;

    pc_ptr = (uint32_t *)pc_start;
    /* assume that the arch use little endian 
     * only change the low 16bits
     * the upper 16bits belong to other instruction
     * */
    inst = *pc_ptr;

    offset = pc_end - (pc_start + 4);
    if (offset < ((1 << 10) - 1) && offset > -((1 << 10) - 1)) {
        inst = inst & 0xfffff800;
        inst = inst | BITS(offset, 1, 11);
        *pc_ptr = inst;
    } else {
        abort();
    }
    return 0;
}

static int modify_thumb_br_cond_off(TCGContext *s, uint8_t *pc_start, uint8_t *pc_end)
{
    int offset;
    uint32_t inst;
    uint32_t *pc_ptr;

    pc_ptr = (uint32_t *)pc_start;
    /* assume that the arch use little endian 
     * only change the low 16bits
     * the upper 16bits belong to other instruction
     * */
    inst = *pc_ptr;

    offset = pc_end - (pc_start + 4);
    if (offset < ((1 << 7) - 1) && offset > -((1 << 7) - 1)) {
        inst = inst & 0xffffff00;
        inst = inst | BITS(offset, 1, 8);
        *pc_ptr = inst;
    } else {
        abort();
    }
    return 0;
}

/* complete */
static void cemit_thumb_exit_tb(TCGContext *s, uint32_t target)
{
    TranslationBlock *tb;
    Inst *patch_pc;

    tb = s->cur_tb;
    /* push r0 */
    cemit_thumb_push(s, REG_R0);

    /* add r0, pc, off */
    patch_pc = s->code_ptr;
    cemit_thumb_add_to_pc(s, REG_R0, s->code_ptr, s->code_ptr);

    /* back to translator */
    /* push r1 */
    cemit_thumb_push(s, REG_R1);
    /* mov r1, tb_ret_addr */
    cemit_thumb_mov_imm32(s, REG_R1, (uint32_t)s->tb_ret_addr);
    /* bx r1 */
    cemit_thumb_bx_reg(s, REG_R1);

    /* mov pc, r1 */
    //cemit_thumb_mov_special(s, REG_PC, REG_R1);

    /* the add-to-pc instruction assume that the imm and pc both word-aligned
     * so if now the code_ptr isn't word-algned, we must align it by hand.
     */
    if ((uint32_t)s->code_ptr & 0x3) 
        s->code_ptr += 2;
    modify_thumb_addtopc_off(patch_pc, s->code_ptr);

    /* store tb in code cache */
    code_emit32(s->code_ptr, target);
    code_emit32(s->code_ptr, (uint32_t)tb);
}

/* complete */
static void cemit_thumb_exit_tb_ind(TCGContext *s, uint32_t Rt)
{
    TranslationBlock *tb;
    Inst *patch_pc1, *patch_pc2;
    uint32_t reg_free;
    uint32_t inst;

    tb = s->cur_tb;
    /* str Rt, [pc, off] */
    reg_free = find_free_reg(1 << Rt);
    cemit_thumb_push(s, reg_free);
    patch_pc1 = s->code_ptr;
    cemit_thumb_add_to_pc(s, reg_free, s->code_ptr, s->code_ptr);
    cemit_thumb2_datatra_imm(s, 0, Rt, reg_free, 0);
    cemit_thumb_pop(s, reg_free);

    if (s->cur_tb->is_pop_pc) {
        /* pop Rt */
        cemit_thumb_pop(s, Rt);
        /* add sp, sp, 4 */
        inst = 0xb001;
        *s->code_ptr++ = inst & 0xff;
        *s->code_ptr++ = (inst >> 8) & 0xff;
        tb->exit_tb_nopush = 1;
    }

    if (tb->exit_tb_nopush) { 
        /* push r0 */
        cemit_thumb_push(s, REG_R0);
    } else {
        if(Rt != REG_R0) {
            /* pop Rt */
            cemit_thumb_pop(s, Rt);
            /* push r0 */
            cemit_thumb_push(s, REG_R0);
        }
    }

    /* add r0, pc, off */
    patch_pc2 = s->code_ptr;
    cemit_thumb_add_to_pc(s, REG_R0, s->code_ptr, s->code_ptr);

    /* back to translator */
    /* push r1 */
    cemit_thumb_push(s, REG_R1);
    /* mov r1, tb_ret_addr */
    cemit_thumb_mov_imm32(s, REG_R1, (uint32_t)s->tb_ret_addr);
    /* bx r1 */
    cemit_thumb_bx_reg(s, REG_R1);
    /* mov pc, r1 */
    //cemit_thumb_mov_special(s, REG_PC, REG_R1);

    /* the add-to-pc instruction assume that the imm and pc both word-aligned
     * so if now the code_ptr isn't word-algned, we must align it by hand.
     */
    if ((uint32_t)s->code_ptr & 0x3) 
        s->code_ptr += 2;
    modify_thumb_addtopc_off(patch_pc2, s->code_ptr);

    /* store tb in code cache */
    modify_thumb_addtopc_off(patch_pc1, s->code_ptr);
    s->code_ptr += 4;
    code_emit32(s->code_ptr, (uint32_t)tb);
}
static int cemit_thumb_exit_tb_msr(TCGContext *s, uint32_t Rm)
{
    return 0;
}

/* should handle if-then instruction carefully */
static void cemit_thumb2_normal(TCGContext *s, decode_t *ds)
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
        cemit_thumb_push(s, Rm_rep);
        cemit_thumb_mov_imm32(s, Rm_rep, (uint32_t)ds->pc + 2);
        inst = inst & ~(0xf << ds->Rm_pos);
        inst |= (Rm_rep << ds->Rm_pos);
    }
    if (ds->rs_num >= 2 && ds->Rn == REG_PC) {
        Rn_rep = find_free_reg(ds->reg_list);
        ds->reg_list |= 1 << Rn_rep;
        cemit_thumb_push(s, Rn_rep);
        cemit_thumb_mov_imm32(s, Rn_rep, (uint32_t)ds->pc + 2);
        inst = inst & ~(0xf << ds->Rn_pos);
        inst |= (Rn_rep << ds->Rn_pos);
    }
    if (ds->rs_num >= 3 && ds->Rs == REG_PC) {
        Rs_rep = find_free_reg(ds->reg_list);
        ds->reg_list |= 1 << Rs_rep;
        cemit_thumb_push(s, Rs_rep);
        cemit_thumb_mov_imm32(s, Rs_rep, (uint32_t)ds->pc + 2);
        inst = inst & ~(0xf << ds->Rs_pos);
        inst |= (Rs_rep << ds->Rs_pos);
    }

    *s->code_ptr++ = ((inst >> 16) & 0xff);
    *s->code_ptr++ = ((inst >> 24) & 0xff);
    *s->code_ptr++ = (inst & 0xff);
    *s->code_ptr++ = ((inst >> 8) & 0xff);

    if (ds->rs_num >= 3 && ds->Rs == REG_PC) {
        cemit_thumb_pop(s, Rs_rep);
    }
    if (ds->rs_num >= 2 && ds->Rn == REG_PC) {
        cemit_thumb_pop(s, Rn_rep);
    }
    if (ds->rs_num >= 1 && ds->Rm == REG_PC) {
        cemit_thumb_pop(s, Rm_rep);
    }

}

static bool write_thumb2_pc(TCGContext *s, decode_t *ds, uint32_t rd_pos, uint32_t reg_free)
{
    uint32_t inst;
    //uint32_t *patch_stub1, *patch_stub2;

    inst = ds->inst;
    inst = inst & ~(0xf << rd_pos);
    inst |= (reg_free << rd_pos);
    ds->inst = inst;

#if 0
    if (ds->cond != COND_AL) {
        patch_stub1 = s->code_ptr;
        /* (cond)b patch_stub1 */
        cemit_thumb_branch(s, ds->cond, s->code_ptr, NEED_PATCH); 

        target = ds->pc + 4;
        patch_stub2 = s->code_ptr;
        /* b patch_stub2 */
        cemit_thumb_branch(s, COND_AL, s->code_ptr, NEED_PATCH);
        /* patch_stub2: */
        modify_br_off(patch_stub2, s->code_ptr);
        cemit_thumb_exit_tb(s, target);

        /* patch_stub1: */
        modify_thumb_br_off(patch_stub1, s->code_ptr);
    }

#endif

    cemit_thumb_push(s, reg_free);
    ds->reg_list |= 1 << reg_free;
    cemit_thumb2_normal(s, ds);
    cemit_thumb_exit_tb_ind(s, reg_free);

    return true;
}

static bool try_emit_thumb2_normal(TCGContext *s, decode_t *ds)
{
    uint32_t reg_free;

    reg_free = find_free_reg(ds->reg_list);

    /* the instruction may have two destination registers,
     * but ONLY one dest_reg can be REG_PC
     */
    if (ds->rd_num >= 1 && ds->Rd == REG_PC) {
        return write_thumb2_pc(s, ds, ds->Rd_pos, reg_free);
    } else if (ds->rd_num == 2 && ds->Rd2 == REG_PC) {
        return write_thumb2_pc(s, ds, ds->Rd2_pos, reg_free);
    } else {
        cemit_thumb2_normal(s, ds);
        return false;
    }

    return false;
}

static bool xlate_thumb2_br_reg(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    /* there are 3 instructions in total.
     * table branch
     * bxj reg 
     */
    struct TranslationBlock *tb;
    uint32_t inst;
    //uint32_t pc;
    //uint32_t target;
    //uint32_t *patch_stub1, *patch_stub2;
    uint32_t reg_free, reg_free2;
    
    inst = ds->inst;
    //pc = (uint32_t)ds->pc;

    if (BITS(inst, 25, 4) == 0x4) {
        /* tbb/tbh */
        /* tbb -> ldrb + exit_tb
         * tbh -> ldrh + exit_tb */ ds->Rm = BITS(inst, 16, 4); ds->Rm_pos = 16;
        ds->Rn = BITS(inst, 0, 4);
        ds->Rn_pos = 0;
        s->cur_tb->exit_tb_nopush = 0;
        reg_free = find_free_reg((1 << ds->Rn) | (1 << ds->Rm));
        cemit_thumb_push(s, reg_free);

        if (inst & (1 << 4)) {
            /* tbh */
            inst = 0xf8300010;
        } else { /* tbb */
            inst = 0xf8500010 ;
        }

        if (ds->Rm == REG_PC) {
            cemit_thumb_mov_imm32(s, reg_free, (uint32_t)ds->pc + 2);
            inst = inst | (reg_free << 16) | (reg_free << 12) | (ds->Rn); 
        } else {
            inst = inst | (ds->Rm << 16) | (reg_free << 12) | ds->Rn;
        }
        *s->code_ptr++ = ((inst >> 16) & 0xff);
        *s->code_ptr++ = ((inst >> 24) & 0xff);
        *s->code_ptr++ = (inst & 0xff);
        *s->code_ptr++ = ((inst >> 8) & 0xff);
        reg_free2 = find_free_reg((1 << ds->Rn) | (1 << ds->Rm) | (1 << reg_free));
        /* push reg_free2 */
        cemit_thumb_push(s, reg_free2);
        /* mov reg_free, pc_imm32 */
        cemit_thumb_mov_imm32(s, reg_free2, (uint32_t)ds->pc + 2);
        /* add reg_free, reg_free, reg_free2 */
        inst = 0xeb000000 | (reg_free2 << 16) | reg_free << 8 | reg_free | (0x0 << 4) 
                        | (BITS(0x1, 2, 2) << 12) | (BITS(0x1, 0, 2) << 6);
        *s->code_ptr++ = ((inst >> 16) & 0xff);
        *s->code_ptr++ = ((inst >> 24) & 0xff);
        *s->code_ptr++ = (inst & 0xff);
        *s->code_ptr++ = ((inst >> 8) & 0xff);
        
        /* pop reg_free */
        cemit_thumb_pop(s, reg_free2);

        cemit_thumb_exit_tb_ind(s, reg_free);
        return true;
    } else if((inst & 0xfff0ffff) == 0xf3c08f00) {
        /* bxj rm */
        tb->may_change_state = 1;
        s->cur_tb->exit_tb_nopush = 0;
        cemit_thumb_exit_tb_ind(s, BITS(inst, 16, 4));
        return true;
    }

    return false;
}

static bool xlate_thumb2_br_imm(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    /* there are 3 instructions in total:
     * blx imm
     * b imm
     * bl imm
     * conditional branch
     */
    uint32_t inst;
    int target, target2;
    //uint32_t pc;
    uint8_t *patch_stub1, *patch_stub2;
    struct TranslationBlock *tb;

    inst = ds->inst;
    tb = s->cur_tb;

    switch (inst & 0x5000) {
        case 0x0:
            /* conditional branch */

            /* offset[11:1] = inst[10:0] */
            target = (inst & 0x7ff) << 1;
            /* target[17:12] = inst[21:16].  */
            target |= (inst & 0x003f0000) >> 4;
            /* target[31:20] = inst[26].  */
            target |= ((int32_t)((inst << 5) & 0x80000000)) >> 11;
            /* target[18] = inst[13].  */
            target |= (inst & (1 << 13)) << 5;
            /* target[19] = inst[11].  */
            target |= (inst & (1 << 11)) << 8;

            target += (uint32_t)ds->pc + 2;

            patch_stub1 = s->code_ptr;
            cemit_thumb_br_cond(s, BITS(inst, 22, 4), s->code_ptr, s->code_ptr);

            patch_stub2 = s->code_ptr;
            target2 = (uint32_t)ds->pc + 2;
            cemit_thumb_br_uncond(s, s->code_ptr, s->code_ptr);
            /* patch_stub2 */
            modify_thumb_br_uncond_off(s, patch_stub2, s->code_ptr);
            cemit_thumb_exit_tb(s, target2);
            /* patch_stub1 */
            modify_thumb_br_cond_off(s, patch_stub1, s->code_ptr);
            cemit_thumb_exit_tb(s, target);

            break;
        case 0x1000: case 0x4000: case 0x5000:
            /* b imm */
            /* blx imm */
            /* bl imm */
            target = ((int32_t)inst << 5) >> 9 & ~(int32_t)0xfff;
            /* hw1[10:0] -> target[11:1].  */
            target |= (inst & 0x7ff) << 1; 
            /* (~hw2[13, 11] ^ target[24]) -> offset[23,22]
             * target[24:22] already have the same value because of the
             * sign extension above. 
             */
            target ^= ((~inst) & (1 << 13)) << 10;
            target ^= ((~inst) & (1 << 11)) << 11;

            target += (uint32_t)ds->pc + 2;

            if (inst & (1 << 14)) {
                cemit_thumb_mov_imm32(s, REG_LR, ((uint32_t)ds->pc + 2) | 1);
            }

            if (inst & (1 << 12)) {
                /* b/bl */
                cemit_thumb_exit_tb(s, target);
            } else {
                /* blx 
                 * toARM = true
                 */
                tb->may_change_state = 1;
                target &= ~(uint32_t)2;
                cemit_thumb_exit_tb(s, target);
            }
            break;
        }

    return true;
}

static bool xlate_thumb2_datapro_reg(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    /* Halfword pack.  */
    /* Data processing register constant shift.  */
    /* Register controlled shift.  */
    /* Sign/zero extend.  */
    /* SIMD add/subtract.  */

    uint32_t inst;

    inst = ds->inst;

    ds->Rd = BITS(inst, 8, 4);
    ds->Rd_pos = 8;
    ds->Rm = BITS(inst, 0, 4);
    ds->Rm_pos = 0;
    ds->Rn = BITS(inst, 16, 4);
    ds->Rn_pos = 16;
    ds->rd_num = 1;
    ds->rs_num = 2;
    ds->reg_list = (1 << ds->Rd) | (1 << ds->Rm) | (1 << ds->Rn);

    switch (BITS(inst, 25, 4)) {
        case 0x5:
            /* data processing: constant shift */
            return try_emit_thumb2_normal(s, ds);
            break;
        case 0xd:
            return try_emit_thumb2_normal(s, ds);
            break;
        default: 
            abort();
    }

    return false;
}

/* complete */
static bool xlate_thumb2_datapro_imm(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    /* the type of correlated instructions is:
     * general data_pro_imm
     */

    uint32_t inst;
    uint32_t rs_idx, rd_idx;

    inst = ds->inst;
    rs_idx = rd_idx = 0;
    ds->reg_dst[rd_idx].reg = BITS(inst, 8, 4);
    ds->reg_dst[rd_idx].reg_pos = 8;
    rd_idx++;
    ds->reg_src[rs_idx].reg = BITS(inst, 16, 4);
    ds->reg_src[rs_idx].reg_pos = 16;
    rs_idx++;

    ds->Rd = BITS(inst, 8, 4);
    ds->Rd_pos = 8;
    ds->Rm = BITS(inst, 16, 4);
    ds->Rm_pos = 16;

    ds->reg_list = (1 << ds->Rd) | (1 << ds->Rm);

    /* will handle rd == REG_PC and rm == REG_PC */
    return try_emit_thumb2_normal(s, ds);
}

static bool xlate_thumb2_datatra_reg(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    /* the type of correlated instructions is:
     * other ld/st
     * ld/st ex
     * muti ld/st
     */

    uint32_t inst;
    uint32_t reg_free;

    inst = ds->inst;
    ds->Rd = BITS(inst, 12, 4);
    ds->Rd_pos = 12;
    ds->Rm = BITS(inst, 16, 4);
    ds->Rm_pos = 16;

    switch (BITS(inst, 25, 4)) {
        case 0x4:
            if (BITS(inst, 22, 1) == 0x1) {
                /* ldrd/strd  */
                if (inst & 0x01200000) {
                    if ((inst & (1 << 20))) {
                        /* ldrd */
                        ds->Rd2 = BITS(inst, 8, 4);
                        ds->Rd2_pos = 8;
                        ds->rd_num = 2;
                        ds->rs_num = 1;
                        ds->reg_list = (1 << ds->Rd) | (1 << ds->Rd2) | (1 << ds->Rm);
                        return try_emit_thumb2_normal(s, ds);
                    } else {
                        /* strd */
                        ds->Rn = BITS(inst, 8, 4);
                        ds->Rn_pos = 8;
                        ds->Rs = BITS(inst, 12, 4);
                        ds->Rs_pos = 12;
                        ds->rd_num = 0;
                        ds->rs_num = 3;
                        ds->reg_list = (1 << ds->Rm) | (1 << ds->Rn) | (1 << ds->Rs);
                        cemit_thumb2_normal(s, ds);
                    }
                } else if (BITS(inst, 23, 1) == 0x0) {
                    /* Load/store exclusive word.  */
                    if ((inst & (1 << 20))) {
                        /* ldrex */
                        ds->rd_num = 1;
                        ds->rs_num = 1;
                        ds->reg_list = (1 << ds->Rd) | (1 << ds->Rm);
                        return try_emit_thumb2_normal(s, ds);
                    } else {
                        /* strex */
                        ds->Rn = BITS(inst, 8, 4);
                        ds->Rn_pos = 8;
                        ds->Rs = BITS(inst, 12, 4);
                        ds->Rs_pos = 12;
                        ds->rd_num = 0;
                        ds->rs_num = 3;
                        ds->reg_list = (1 << ds->Rm) | (1 << ds->Rn) | (1 << ds->Rs);
                        cemit_thumb2_normal(s, ds);
                    }

                } else {
                    switch (BITS(inst, 4, 4)) {
                        case 0x4: case 0x5:
                            if ((inst & (1 << 20))) {
                                /* ld */
                                ds->rd_num = 1;
                                ds->rs_num = 1;
                                ds->reg_list = (1 << ds->Rd) | (1 << ds->Rm);
                                s->cur_tb->may_change_state = (ds->Rd == REG_PC);
                                return  try_emit_thumb2_normal(s, ds);
                            } else {
                                /* st */
                                ds->Rn = BITS(inst, 0, 4);
                                ds->Rn_pos = 0;
                                ds->Rs = BITS(inst, 12, 4);
                                ds->Rs_pos = 12;
                                ds->rd_num = 0;
                                ds->rs_num = 3;
                                ds->reg_list = (1 << ds->Rm) | (1 << ds->Rn) | (1 << ds->Rs);
                                cemit_thumb2_normal(s, ds);
                            }
                            break;
                        case 0x7:
                            if ((inst & (1 << 20))) {
                                s->cur_tb->may_change_state = (ds->Rd == REG_PC);
                                ds->Rd2 = BITS(inst, 8, 4);
                                ds->Rd2_pos = 8;
                                ds->rd_num = 2;
                                ds->rs_num = 1;
                                ds->reg_list = (1 << ds->Rd) | (1 << ds->Rd2) | (1 << ds->Rm);
                                return try_emit_thumb2_normal(s, ds);
                            } else {
                                ds->Rn = BITS(inst, 8, 4);
                                ds->Rn_pos = 8;
                                ds->Rs = BITS(inst, 12, 4);
                                ds->Rs_pos = 12;
                                ds->rd_num = 0;
                                ds->rs_num = 3;
                                ds->reg_list = (1 << ds->Rm) | (1 << ds->Rn) | (1 << ds->Rs);
                                cemit_thumb2_normal(s, ds);
                            }
                            break;
                        default:
                            abort();

                    }
                }
            } else {
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
                       s->cur_tb->may_change_state = 1;
                       inst = inst & ~(1 << 15);
                       ds->inst = inst;
                       cemit_thumb2_normal(s, ds);
                       ds->reg_list = (1 << ds->Rm);
                       reg_free = find_free_reg(ds->reg_list);
                       cemit_thumb_push(s, reg_free);
                       inst = inst & ~((1 << 16) - 1);
                       inst = inst | (1 << reg_free);
                       cemit_thumb2_normal(s, ds);
                       cemit_thumb_exit_tb_ind(s, reg_free);
                       return true;
                   } else {
                       cemit_thumb2_normal(s, ds);
                   }

               } else {
                   /* stm/push */
                   cemit_thumb2_normal(s, ds);
               }

            }
            break;
        default:
            abort();
    }
    return false;
}

/* complete */
static bool xlate_thumb2_datatra_imm(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    /* the type of correlated instructions is:
     * general ld/st imm offset
     */

    uint32_t inst;
    uint32_t addr;
    uint32_t reg_free;
    TranslationBlock *tb;
    uint8_t *patch_pc1, *patch_pc2;
    uint8_t *patch_pc3, *patch_pc4;

    inst = ds->inst;

    ds->Rd = BITS(inst, 12, 4);
    ds->Rd_pos = 12;
    ds->Rm = BITS(inst, 16, 4);
    ds->Rm_pos = 16;
    ds->reg_list = (1 << ds->Rd) | (1 << ds->Rm);
    ds->rd_num = 1;
    ds->rs_num = 1;
    
    if (inst & (1 << 20)) {
        /* ld */
        if (ds->Rm == REG_PC) {
            /* pc +- imm12 */
            /* align pc */
            addr = (uint32_t)ds->pc + 2;
            addr &= 0xfffffffc;
            if (inst & (1 << 23)) {
                addr += BITS(inst, 0, 12);
            } else {
                addr -= BITS(inst, 0, 12);
            }
            reg_free = find_free_reg(1 << ds->Rd);
            /* push reg_free */
            cemit_thumb_push(s, reg_free);
            /* mov reg_free, addr */
            cemit_thumb_mov_imm32(s, reg_free, addr); 
            inst |= (1 << 23);
            inst &= 0xfff0f000;
            inst |= (reg_free << 16);
            ds->inst = inst;
            ds->Rm = reg_free;
            ds->reg_list |= (1 << reg_free);
            if (ds->Rd == REG_PC) {
                /* rd == pc */
                s->cur_tb->may_change_state = 1;
                reg_free = find_free_reg(ds->reg_list);
                inst = ds->inst;
                inst = inst & ~(0xf << ds->Rd_pos);
                inst |= (reg_free << ds->Rd_pos);
                ds->inst = inst;
                cemit_thumb_push(s, reg_free);
                ds->reg_list |= 1 << reg_free;
                /* load the destination addr into reg_free */
                cemit_thumb2_normal(s, ds);

                tb = s->cur_tb;
                /* str reg_free, [pc, off] */
                patch_pc1 = s->code_ptr;
                cemit_thumb2_datatra_imm(s, (1 << 0), reg_free, REG_PC, 0);
                cemit_thumb_pop(s, reg_free);

                if(ds->Rm != REG_R0) {
                    /* pop ds->Rm */
                    cemit_thumb_pop(s, ds->Rm);
                    /* push r0 */
                    cemit_thumb_push(s, REG_R0);
                }

                /* add r0, pc, off */
                patch_pc2 = s->code_ptr;
                cemit_thumb_add_to_pc(s, REG_R0, s->code_ptr, s->code_ptr);

                /* back to translator */
                /* push r1 */
                cemit_thumb_push(s, REG_R1);
                /* mov r1, tb_ret_addr */
                cemit_thumb_mov_imm32(s, REG_R1, (uint32_t)thumb_tb_ret_addr);
                /* mov pc, r1 */
                cemit_thumb_mov_special(s, REG_PC, REG_R1);

                modify_thumb_addtopc_off(patch_pc2, s->code_ptr);
                /* store tb in code cache */
                modify_thumb2_datatra_imm(s, patch_pc1, s->code_ptr);
                s->code_ptr += 4;
                code_emit32(s->code_ptr, (uint32_t)tb);
                return true;
            } else {
                cemit_thumb2_normal(s, ds);
                cemit_thumb_pop(s, reg_free);
                return false;
            }
        } else if (ds->Rm == REG_SP && ds->Rd == REG_PC) {
            /* str r0, [pc # offset] */
            fprintf(stderr, "s->code_ptr is %x\n", s->code_ptr);
            cemit_store_pc_off(s, &patch_pc1, REG_R0, s->code_ptr);

            /* inst (with rm = r0) */
            inst = ds->inst;
            inst = inst & ~(0xf << ds->Rd_pos);
            inst |= (REG_R0 << ds->Rd_pos);
            ds->inst = inst;
            cemit_thumb2_normal(s, ds);

            /* str r0, [stub_target] */
            cemit_store_pc_off(s, &patch_pc2, REG_R0, s->code_ptr);

            /* ldr r0, [pc # offset] */
            cemit_load_pc_off(s, &patch_pc3, REG_R0, 0);

            cemit_thumb_push(s, REG_R0);

            /* add r0, pc, off */
            patch_pc4 = s->code_ptr;
            cemit_thumb_add_to_pc(s, REG_R0, s->code_ptr, s->code_ptr);

            /* back to translator */
            /* push r1 */
            cemit_thumb_push(s, REG_R1);
            /* mov r1, tb_ret_addr */
            cemit_thumb_mov_imm32(s, REG_R1, (uint32_t)s->tb_ret_addr);
            /* bx r1 */
            cemit_thumb_bx_reg(s, REG_R1);

            if ((uint32_t)s->code_ptr & 0x3) 
                s->code_ptr += 2;
            modify_thumb_addtopc_off(patch_pc4, s->code_ptr);

            modify_thumb_addtopc_off(patch_pc2, s->code_ptr);
            s->code_ptr += 4;
            /* store tb in code cache */
            code_emit32(s->code_ptr, (uint32_t)s->cur_tb);
            modify_thumb_addtopc_off(patch_pc1, s->code_ptr);
            modify_thumb_addtopc_off(patch_pc3, s->code_ptr);
            s->code_ptr += 4;

            return true;
        }

        return try_emit_thumb2_normal(s, ds);
    } else {
        /* st */
        if (ds->Rm == REG_PC) {
            fprintf(stderr, "Rn cannot be r15!\n");
            abort();
        }
        /* for store instruction Rd is the src regster */
        ds->Rm = BITS(inst, 12, 4);
        ds->Rm_pos = 12;
        ds->rs_num = 1;

        /* simply copy to code cache */
        cemit_thumb2_normal(s, ds);
        return false;
    }

    return false;
}

static int xlate_thumb2_statetra_reg(CPUARMState *env, TCGContext *s, decode_t *ds)
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
        /* mrs rd, cpsr */
        if (Rd == REG_PC) {
            write_thumb2_pc(s, ds, rd_pos, reg_free);
        } else {
            cemit_thumb2_normal(s, ds);
        }
    } else {
        /*msr cpsr, rm*/
        tb->exit_tb_nopush = 1;
        cemit_thumb_exit_tb_msr(s, Rm);
    }
    return 0;
}
static int xlate_thumb2_statetra_imm(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    abort();
}

static int xlate_thumb2_exception(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    cemit_thumb2_normal(s, ds);
    return 0;
}

static int xlate_thumb2_coprocessor(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    cemit_thumb2_normal(s, ds);
    return 0;
}

static int xlate_thumb2_other(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    cemit_thumb2_normal(s, ds);
    return 0;
}
static int xlate_thumb2_nop(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    cemit_thumb2_normal(s, ds);
    return 0;
}

void disas_thumb2_inst(CPUARMState *env, TCGContext *s, decode_t *ds, uint16_t inst_hw1)
{
    uint32_t op;
    uint32_t inst;

    ds->pc += 2;
    inst = arm_lduw_code(env, (uint32_t)ds->pc, ds->bswap_code);
    inst |= (uint32_t)inst_hw1 << 16;
    ds->inst = inst;

    if ((inst & 0xf800e800) != 0xf000e800) {
        ARCH(6T2);
    }

    switch (BITS(inst, 25, 4)) {
    case 0x0: case 0x1: case 0x2: case 0x3:
        /* 16-bit instructions.  Should never happen.  */
        abort();
    case 0x4:
        if (BITS(inst, 22, 1) == 0x1) {
            /* Other load/store, table branch.  */
            if (inst & 0x01200000) {
                ds->func = xlate_thumb2_datatra_reg;

            } else if (BITS(inst, 23, 1) == 0x0) {
                /* Load/store exclusive word.  */
                ds->func = xlate_thumb2_datatra_reg;

            } else if ((inst & (1 << 6)) == 0) {
                /* Table Branch.  */
                ds->func = xlate_thumb2_br_reg;
            } else {
                /* Load/store exclusive byte/halfword/doubleword.  */
                ARCH(7);
                op = (inst >> 4) & 0x3;
                if (op == 2) {
                    goto illegal_op;
                }

                ds->func = xlate_thumb2_datatra_reg;
            }
        } else {
            /* Load/store multiple, RFE, SRS.  */
            if (((inst >> 23) & 1) == ((inst >> 24) & 1)) {
                /* Not available in user mode.  */
                /* rfe, srs */
                if (IS_USER(s))
                    goto illegal_op;
                abort();
            } else {
                /* Load/store multiple.  */
                ds->func = xlate_thumb2_datatra_reg;
            }
        }
        break;
    case 5:
        op = (inst >> 21) & 0xf;
        if (op == 6) {
            /* Halfword pack.  */
            ds->func = xlate_thumb2_datapro_reg;
        } else {
            /* Data processing register constant shift.  */
            ds->func = xlate_thumb2_datapro_reg;
        }
        break;
    case 13: /* Misc data processing.  */
        op = ((inst >> 22) & 6) | ((inst >> 7) & 1);
        if (op < 4 && (inst & 0xf000) != 0xf000)
            goto illegal_op;
        switch (op) {
            case 0: 
                /* Register controlled shift.  */
                ds->func = xlate_thumb2_datapro_reg;
                break;
            case 1: 
                /* Sign/zero extend.  */
                ds->func = xlate_thumb2_datapro_reg;
                break;
            case 2: 
                /* SIMD add/subtract.  */
                ds->func = xlate_thumb2_datapro_reg;
                break;
            case 3: /* Other data processing.  */
                op = ((inst >> 17) & 0x38) | ((inst >> 4) & 7);
                if (op < 4) {
                    /* Saturating add/subtract.  */
                    ds->func = xlate_thumb2_datapro_reg;
                } else {
                    ds->func = xlate_thumb2_datapro_reg;
                }
                break;
            case 4: case 5: /* 32-bit multiply.  Sum of absolute differences.  */
                ds->func = xlate_thumb2_datapro_reg;
                break;
            case 6: case 7: /* 64-bit multiply, Divide.  */
                ds->func = xlate_thumb2_datapro_reg;
                break;
        }
        break;
    case 6: case 7: case 14: case 15:
        /* Coprocessor.  */
            ds->func = xlate_thumb2_coprocessor;
        break;
    case 8: case 9: case 10: case 11:
        if (inst & (1 << 15)) {
            /* Branches, misc control.  */
            if (inst & 0x5000) {
                /* Unconditional branch.  */
                /* bl/b blx imm. */
                ds->func = xlate_thumb2_br_imm;
            } else if (((inst >> 23) & 7) == 7) {
                /* Misc control */
                if (inst & (1 << 13))
                    goto illegal_op;

                if (inst & (1 << 26)) {
                    /* Secure monitor call (v6Z) */
                    goto illegal_op; /* not implemented.  */
                } else {
                    op = (inst >> 20) & 7;
                    switch (op) {
                    case 0: /* msr cpsr.  */
                        /* fall through */
                    case 1: /* msr spsr.  */
                        ds->func = xlate_thumb2_statetra_reg;
                        break;
                    case 2: /* cps, nop-hint.  */
                        if (((inst >> 8) & 7) == 0) {
                            /* nop-hint */
                            ds->func = xlate_thumb2_nop;
                            break;
                        }
                        /* Implemented as NOP in user mode.  */
                        if (IS_USER(s)) {
                            ds->func = xlate_thumb2_nop;
                        }
                        break;
                    case 3: /* Special control operations.  */
                        ARCH(7);
                        op = (inst >> 4) & 0xf;
                        switch (op) {
                        case 2: /* clrex */
                            ds->func = xlate_thumb2_other;
                            break;
                        case 4: /* dsb */
                        case 5: /* dmb */
                        case 6: /* isb */
                            /* These execute as NOPs.  */
                            ds->func = xlate_thumb2_nop;
                            break;
                        default:
                            abort();
                        }
                        break;
                    case 4: 
                        /* bxj reg */
                        /* Trivial implementation equivalent to bx.  */
                        ds->func = xlate_thumb2_br_reg;
                        break;
                    case 5: /* Exception return.  */
                        if (IS_USER(s)) {
                            abort();
                        }
                        break;
                    case 6: /* mrs cpsr.  */
                        ds->func = xlate_thumb2_statetra_reg;
                        break;
                    case 7: /* mrs spsr.  */
                        /* Not accessible in user mode.  */
                        if (IS_USER(s) || IS_M(env))
                            abort();
                        break;
                    }
                }
            } else {
                /* Conditional branch.  */
                op = (inst >> 22) & 0xf;
                /* Generate a conditional jump to next instruction.  */
                ds->func = xlate_thumb2_br_imm;
            }
        } else {
            /* Data processing immediate.  */
            ds->rd_num = 1;
            ds->rs_num = 1;

            if (inst & (1 << 25)) {
                if (inst & (1 << 24)) {
                    if (inst & (1 << 20))
                        abort();
                    /* Bitfield/Saturate.  */
                    ds->func = xlate_thumb2_datapro_imm;
                    if (BITS(inst, 21, 3) == 0x3) {
                        /* bfc */
                        ds->rs_num = 0;
                    }
                } else {
                    ds->func = xlate_thumb2_datapro_imm;
                    if (inst & (1 << 22)) {
                        /* mov, plain  16-bit immediate */
                        ds->rs_num = 0;
                    }
                }
            } else {
                /* modified 12-bit immediate.  */
                ds->func = xlate_thumb2_datapro_imm;
                switch (BITS(inst, 21, 4)) {
                    case 0x0: case 0x4: case 0x8: case 0xd:
                        if (BITS(inst, 8, 4) == REG_PC && BITS(inst, 20, 1) == 0x1) {
                            ds->rd_num = 0;
                        }
                        break;
                    case 0x2: case 0x3:
                        if (BITS(inst, 16, 4) == REG_PC) {
                            ds->rs_num = 0;
                        }
                        break;
                }
            }
        }
        break;
    case 12: /* Load/store single data item.  */
        ds->func = xlate_thumb2_datatra_imm;
        break;
    default:
        abort();
    }
    return;
illegal_op:
    abort();
}

static int cemit_thumb_normal(TCGContext *s, decode_t *ds)
{
    uint32_t inst;

    inst = ds->inst;

    *s->code_ptr++ = (inst & 0xff);
    *s->code_ptr++ = ((inst >> 8) & 0xff);
    return 0;

}

static int xlate_thumb_br_reg(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    uint32_t inst, reg;
    uint32_t pc;
    uint8_t *patch_stub1, *patch_stub2;
    uint32_t target1, target2;
    uint32_t offset;

    inst = ds->inst;

    if ((inst & 0xff07) == 0x4700) {
        reg = BITS(inst, 3, 4);
        s->cur_tb->exit_tb_nopush = 1;
        /* br/ex */
        if (inst & (1 << 7)) {
            /* blx reg */
            /* mov pc, r1 */
            s->cur_tb->may_change_state = 1;
            cemit_thumb_mov_imm32(s, REG_LR, pc + 2);
            cemit_thumb_exit_tb_ind(s, reg);
        } else {
            /* bx reg */
            s->cur_tb->may_change_state = 1;
            cemit_thumb_exit_tb_ind(s, reg);
        }
    } else if ((inst & 0xf500) == 0xb100) {
        /* compare and branch on (non)zero */
        patch_stub1 = s->code_ptr;

        target1 = (BITS(inst, 9, 1) << 5) | BITS(inst, 3, 5);
        target1 = target1 << 1;
        target1 = ds->pc + 4 + target1;

        /* cbz|cbnz patch_stub1 */
        inst = inst & 0xfd07;
        *s->code_ptr++ = inst & 0xff;
        *s->code_ptr++ = (inst >> 8) & 0xff;

        patch_stub2 = s->code_ptr;
        target2 = ds->pc + 2;
        /* b patch_stub2 */
        cemit_thumb_br_uncond(s, s->code_ptr, s->code_ptr);
        /* patch_stub2 */
        modify_thumb_br_uncond_off(s, patch_stub2, s->code_ptr);
        cemit_thumb_exit_tb(s, target2);
        /* patch_stub1 */
        /* modify cbz|cbnz offset */
        offset = s->code_ptr - (patch_stub1 + 4);
        inst =  inst | (BITS(offset, 6, 1) << 9) | (BITS(offset, 1, 5) << 3);
        *patch_stub1 = inst & 0xff;
        *(patch_stub1 + 1) = (inst >> 8) & 0xff;
        cemit_thumb_exit_tb(s, target1);
    } else {
        abort();
    }
}

static int xlate_thumb_br_imm(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    uint32_t inst;
    uint8_t *patch_stub1, *patch_stub2;
    uint32_t reg_free;
    uint32_t target, target2;
    uint32_t cond;

    inst = ds->inst;

    if (BITS(inst, 13, 3) == 0x6) {
        /* conditional branch */
        target = ((int)inst << 24) >> 24;
        target = target << 1;
        target = (ds->pc + 4) + target;  
        cond = BITS(inst, 8, 4);

        patch_stub1 = s->code_ptr;
        cemit_thumb_br_cond(s, cond, s->code_ptr, s->code_ptr);

        patch_stub2 = s->code_ptr;
        target2 = ds->pc + 2;
        cemit_thumb_br_uncond(s, s->code_ptr, s->code_ptr);
        /* patch_stub2 */
        modify_thumb_br_uncond_off(s, patch_stub2, s->code_ptr);
        cemit_thumb_exit_tb(s, target2);
        /* patch_stub1 */
        modify_thumb_br_cond_off(s, patch_stub1, s->code_ptr);
        cemit_thumb_exit_tb(s, target);

    } else if (BITS(inst, 13, 3) == 0x7) {
        /* unconditional branch */
        target = ((int)inst << 21) >> 21;
        target = target << 1;
        target = (ds->pc + 4) + target;  
        cemit_thumb_exit_tb(s, target);
    } else {
        abort();
    }

}

static bool xlate_thumb_datatra_reg(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    uint32_t inst;

    inst = ds->inst;

    if ((inst & 0xf000) == 0x6000) {
        /* ld/st register offset */
       cemit_thumb_normal(s, ds); 
    } else if ((inst & 0xf600) == 0xb400) {
        /* push/pop */
        if (inst & (1 << 11)) {
            /* pop */
            if (inst & (1 << 8)) {
                /* write pc 
                 * should pop 2 items in epilogue
                 */ 
                s->cur_tb->may_change_state = 1;
                inst = inst & ~(1 << 8);
                ds->inst = inst;
                cemit_thumb_normal(s, ds);
                cemit_thumb_push(s, REG_R0);
                //inst = inst & ~((1 << 8) - 1);
                //inst = inst | (1 << REG_R0);
                inst = 0x9801 | (REG_R0 << 8);
                ds->inst = inst;
                cemit_thumb_normal(s, ds);
                s->cur_tb->is_pop_pc = 1;
                cemit_thumb_exit_tb_ind(s, REG_R0);
                return true;
            } else {
                cemit_thumb_normal(s, ds);
            }
        } else {
            /* push */
            cemit_thumb_normal(s, ds);
        }
    } else if ((inst & 0xf000) == 0xc000) {
        /* ld/st multiple */
        cemit_thumb_normal(s, ds);
    } else {
        abort();
    }

    return false;
}

/* complete */
static bool xlate_thumb_datatra_imm(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    uint32_t inst, reg_free;
    int addr;

    inst = ds->inst;

    if ((inst & 0xf800) == 0x4800) {
        /* load from literal pool */
        reg_free = find_free_reg(1 << BITS(inst, 8, 3));
        /* push reg_free */
        cemit_thumb_push(s, reg_free);
        addr = ds->pc + 4 + (BITS(inst, 0, 8) << 2);
        addr &= ~(uint32_t)2;
        /* mov reg_free, addr */
        cemit_thumb_mov_imm32(s, reg_free, addr);
        /* ld rt, [reg_free, #0] */
        cemit_thumb_datatra_imm(s, (inst & (1 << 11)), reg_free, BITS(inst, 8, 3), 0);
        /* pop reg_free */
        cemit_thumb_pop(s, reg_free);
    } else if ((inst & 0xe000) == 0x6000) {
        /* ld/st word/byte imm offset */
        cemit_thumb_normal(s, ds);
    } else if ((inst & 0xf000) == 0x8000) {
        /* ld/st halfword imm offset */
        cemit_thumb_normal(s, ds);
    } else if ((inst & 0xf000) == 0x9000) {
        /* ld/st stack */
        cemit_thumb_normal(s, ds);
    } else {
        abort();
    }

    return false;
}
static bool xlate_thumb_statetra_reg(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    uint32_t inst;
    inst = ds->inst;

    if (inst & 0xfff7 == 0xb657) {
        /* set endianness */
        /* should set the env */
    } else if (inst & 0xffe8 == 0xb660) {
        /* change process state */
        cemit_thumb_normal(s, ds);
    } else {
        abort();
    } 
    
    return false;
}

static bool xlate_thumb_statetra_imm(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    /* never be called */
    abort();
}

static bool xlate_thumb_exception(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    cemit_thumb_normal(s, ds);
    return false;
}


static bool xlate_thumb_datapro_reg(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    uint32_t inst;
    uint32_t Rd, Rn, Rm;
    uint32_t reg_free;
    uint32_t off;

    inst = ds->inst;
    switch (ds->index) {
        case 0x0:
            /* shift by immediate, move register */
            /* add/subtract register */
            cemit_thumb_normal(s, ds);
            break;
        case 0x2:
            if (BITS(inst, 10, 3) == 0x0) {
                cemit_thumb_normal(s, ds);
            } else if (BITS(inst, 10, 3) == 0x1) {
                /* special data processing */
                Rd = (BITS(inst, 7, 1) << 3) | BITS(inst, 0, 3);
                Rn = (BITS(inst, 7, 1) << 3) | BITS(inst, 0, 3);
                Rm = BITS(inst, 3, 4);

                if (Rd == REG_PC) {
                    reg_free = find_free_reg((1 << Rd) | (1 << Rm));
                    cemit_thumb_push(s, reg_free);
                    off = ds->pc + 4;
                    cemit_thumb_mov_imm32(s, reg_free, off);

                    inst = inst & ~(1 << 7) & ~(1 << 3 - 1);
                    inst = inst | ((BITS(reg_free, 3, 1)) << 7) | (BITS(reg_free, 0, 3));
                    *s->code_ptr++ = (inst & 0xff);
                    *s->code_ptr++ = ((inst >> 8) & 0xff);

                    cemit_thumb_exit_tb_ind(s, reg_free);
                    return true;
                } else {
                    cemit_thumb_normal(s, ds);
                }
            }
            break;
        case 0x5:
            /* sign/zero extend */
            cemit_thumb_normal(s, ds);
            break;
        default:
            abort();
    }
   return false; 
}

static int xlate_thumb_datapro_imm(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    uint32_t inst;
    uint32_t off;

    inst = ds->inst;
    
    switch (ds->index) {
        case 0x0:
            if (BITS(inst, 10, 3) == 0x7) {
                cemit_thumb_normal(s, ds);
            } else {
                abort();
            }
            break;
        case 0x1:
            cemit_thumb_normal(s, ds);
            break;
        case 0x5:
            if (BITS(inst, 12, 1) == 0x0) {
                /* add to sp/pc */
                if (BITS(inst, 11, 1) == 0x0) {
                    /* add to pc */
                    off = ds->pc + 4;
                    off = off + (BITS(inst, 0, 8) << 2);
                    cemit_thumb_mov_imm32(s, BITS(inst, 8, 3), off);
                } else {
                    /* add to sp */
                    cemit_thumb_normal(s, ds);
                }
            } else {
                /* adjust stack pointer */
                cemit_thumb_normal(s, ds);
            }
            break;
        default:
            abort();
    }
    return 0;
}

void disas_thumb_inst(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    uint32_t cond, inst;

    /* should be handled later */
    if (ds->condexec_mask) {
        cond = ds->condexec_cond;
        if (cond != 0xe) {
            ds->condmp = 1;
        }
    }

    inst = arm_lduw_code(env, ds->pc, ds->bswap_code);
    ds->inst = inst;
    ds->index = BITS(inst, 13, 3);
    switch (ds->index) {
        case 0x0:
            switch (BITS(inst, 11, 2)) {
                case 0x0: case 0x1: case 0x2:
                    ds->func = xlate_thumb_datapro_reg;
                    break;
                case 0x3:
                    if (BITS(inst, 10, 1) == 0x0) {
                        ds->func = xlate_thumb_datapro_reg;
                    } else {
                        ds->func = xlate_thumb_datapro_imm;
                    }
            }
            break;
        case 0x1:
            ds->func = xlate_thumb_datapro_imm;
            break;

        case 0x2:
            if (BITS(inst, 12, 1) == 0x1) {
                /* ld/st reg offset */
                ds->func = xlate_thumb_datatra_reg;
                
            } else {
                if (BITS(inst, 11, 1) == 0x1) {
                    /* ld from literal pool */
                    ds->func = xlate_thumb_datatra_imm;
                } else {
                    if (BITS(inst, 10, 1) == 0x0) {
                        /* data-pro reg */
                        ds->func = xlate_thumb_datapro_reg;
                    } else {
                        if (BITS(inst, 8, 2) == 0x3) {
                            /* br/ex */
                            ds->func = xlate_thumb_br_reg;
                        } else {
                            /* special data pro */
                            ds->func = xlate_thumb_datapro_reg;
                        }
                    }
                }
            }
            break;
        case 0x3:
            /* ld/st word/byte imm off */
            ds->func = xlate_thumb_datatra_imm;
            break;
        case 0x4:
            if (BITS(inst, 12, 1) == 0x1) {
                /* ld/st halfword imm off */
                ds->func = xlate_thumb_datatra_imm;
            } else {
                /* ld/st stack */
                ds->func = xlate_thumb_datatra_imm;
            }
            break;
        case 0x5:
            if (BITS(inst, 12, 1) == 0x0) {
                /* add to sp or pc */
                ds->func = xlate_thumb_datapro_imm;
            } else {
                /* miscellaneous inst */
                switch (BITS(inst, 8, 4)) {
                    case 0x0:
                        /* adjust stack pointer */
                        ds->func = xlate_thumb_datapro_imm;
                        break;
                    case 0x1: case 0x3: case 0x9: case 0xb:
                        /* compare and branch */
                        ds->func = xlate_thumb_br_reg;
                        break;
                    case 0x2:
                        /* sign/zero extend */
                        ds->func = xlate_thumb_datapro_reg;
                        break;
                    case 0x4: case 0x5:
                        /* push */
                        ds->func = xlate_thumb_datatra_reg;
                        break;
                    case 0x6:
                        if (inst & 0xfff7 == 0xb650) {
                            /* set endianness */
                            ds->func = xlate_thumb_statetra_reg;
                        } else if (inst & 0xffe8 == 0xb660) {
                            /* change process state */
                            ds->func = xlate_thumb_statetra_reg;
                        } else {
                            /* undefined */
                            abort();
                        }
                    case 0x7: case 0x8:
                        abort();
                    case 0xa:
                        /* reverse byte */
                        ds->func = xlate_thumb_datapro_reg;
                        break;
                    case 0xc: case 0xd:
                        /* pop */
                        ds->func = xlate_thumb_datatra_reg;
                        break;
                    case 0xe:
                        /* software breakpoint */
                        ds->func = xlate_thumb_exception;
                        break;
                    case 0xf:
                        if (inst & 0xf == 0x0) {
                            /* hint */
                        } else {
                            /* if-then */
                        }
                }
            }
            break;
        case 0x6:
            if (BITS(inst, 12, 1) == 0x0) {
                /* ld/st multiple */
                ds->func = xlate_thumb_datatra_reg;
            } else if (BITS(inst, 8, 4) == 0xe) {
                /* undefined instructions */
                abort();
            } else if (BITS(inst, 8, 4) == 0xf) {
                /* service call */
                ds->func = xlate_thumb_exception;
            } else {
                /* conditional branch */
                ds->func = xlate_thumb_br_imm;
            }
            break;
        case 0x7:
            if (BITS(inst, 12, 1) == 0x1) {
                disas_thumb2_inst(env, s, ds, inst);
            } else {
                if (BITS(inst, 11, 1) == 0x1) {
                    disas_thumb2_inst(env, s, ds, inst);
                } else {
                    /* unconditional branch */
                    ds->func = xlate_thumb_br_imm;
                }
            }
            break;
        default :
            break;
    }
    return;

illegal_op:
    abort();
}

int thumb_prolog_init(CPUARMState *env, TCGContext *s)
{
    return 0;
}

