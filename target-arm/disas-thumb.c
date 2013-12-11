#include "decode.h"

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

static int write_thumb2_pc(TCGContext *s, decode_t *ds, uint32_t rd_pos, uint32_t reg_free)
{
    uint32_t inst;
    uint32_t *patch_stub1, *patch_stub2;

    inst = ds->inst;
    inst = inst & ~(0xf << rd_pos) | (reg_free << rd_pos);

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

    cemit_thumb_push(reg_free);
    code_emit32(s->code_ptr, inst);
    cemit_thumb_exit_tb_ind(s, reg_free);
}
static int cemit_thumb_push(TCGContext *s, uint32_t reg)
{

}
static int cemit_thumb_pop(TCGContext *s, uint32_t reg)
{

}
static int cemit_thumb_mov_imm32(TCGContext *s, uint32_t reg, uint32_t imm)
{
    /* need to be implemented later */
    
    return reg_free;
}

/* should handle if-then instruction carefully */
static int cemit_thumb2_normal(TCGContext *s, decode_t *ds)
{
    uint32_t inst;
    uint32_t reg_free;
    int reg_src_pos;

    inst = ds->inst;
    reg_src_pos = ds->reg_src_pos;

    if (reg_src_pos == -1 || (BITS(inst, reg_src_pos, 4) != REG_PC)) {
        /* some instructions use 0x1111 in the source register position, but it doesn't
         * mean the pc register */
        *s->code_ptr++ = ((inst >> 16) & 0xff);
        *s->code_ptr++ = ((inst >> 24) & 0xff);
        *s->code_ptr++ = (inst & 0xff);
        *s->code_ptr++ = ((inst >> 8) & 0xff);
        return 0;
    } else if (BITS(inst, reg_src_pos, 4) == REG_PC) {
        reg_free = find_free_reg(ds->reglist);
        cemit_thumb_push(s, reg_free);

        /* tbb, tbh. ds->pc + 2 */
        /* ldr.. (ds->pc + 2) & ~3 */
        /* others, ds->pc + 4 */
        cemit_thumb_mov_imm32(s, reg_free, ds->pc + 2);

        inst = inst & ~(0xf << reg_src_pos) | (reg_free << reg_src_pos)
        *s->code_ptr++ = ((inst >> 16) & 0xff);
        *s->code_ptr++ = ((inst >> 24) & 0xff);
        *s->code_ptr++ = (inst & 0xff);
        *s->code_ptr++ = ((inst >> 8) & 0xff);; 
        cemit_thumb_pop(s, reg_free);
        return 0;
    } else {
        abort();
    }

    return -1;
}


static void cemit_thumb_exit_tb_ind(TCGContext *s, uint32_t Rt)
{
    TranslationBlock *tb;
    Inst *patch_pc1, *patch_pc2;

    tb = s->cur_tb;
    /* str Rt, [pc, off] */
    patch_pc1 = s->code_ptr;
    cemit_thumb_datatran_imm(s, TRAN_LD, INDEX_PRE, ADDR_NO_WB, ADDR_INC, 
                      Rt, REG_PC, NEED_PATCH);

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
    cemit_thumb_datapro_imm(s, OP_ADD, REG_R0, REG_PC, 0, NEED_PATCH);

    /* back to translator */
    cemit_thumb_branch(s, COND_AL, s->code_ptr, tb_ret_addr);

    modify_thumb_pro_imm(patch_pc2, s->code_ptr);
    /* store tb in code cache */
    code_emit32(s->code_ptr, (Inst)tb);
    modify_thumb_tran_imm(patch_pc1, s->code_ptr);
    s->code_ptr += 4;
}

static int xlate_thumb2_br_reg(CPUARMState *env, TCGContext *s, decode_t *ds)
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

    ds->rm = BITS(inst, 0, 4);
    tb->may_change_state = 1;
    tb->exit_tb_nopush = 1;

                /* tbb -> ldrb + exit_tb
                 * tbh -> ldrh + exit_tb
                 */
                s->cur_tb->exit_tb_nopush = 0;
                reg_free = find_free_reg((1 << rn) | (1 << rm));
                cemit_thumb_push(s, reg_free);

                if (inst & (1 << 4)) {
                    /* tbh */
                    inst = 0xf8300000;
                } else { /* tbb */
                    inst = 0xf8500000 ;
                }

                if (rn == REG_PC) {
                    cemit_thumb_mov_imm32(s, reg_free, ds->pc + 2);
                    inst = inst | (reg_free << 16) | (reg_free << 12) | (rm); 
                } else {
                    inst = inst | (rn << 16) | (reg_free << 12) | rm;
                }
                *s->code_ptr++ = ((inst >> 16) & 0xff);
                *s->code_ptr++ = ((inst >> 24) & 0xff);
                *s->code_ptr++ = (inst & 0xff);
                *s->code_ptr++ = ((inst >> 8) & 0xff);
                cemit_thumb_exit_tb_ind(s, reg_free);
    if (ds->cond != COND_AL) {
        patch_stub1 = s->code_ptr;
        cemit_branch(s, ds->cond, s->code_ptr, NEED_PATCH); 

        target = ds->pc + 4;
        patch_stub2 = s->code_ptr;
        cemit_branch(s, COND_AL, s->code_ptr, NEED_PATCH);
        /* patch_stub2: */
        modify_br_off(patch_stub2, s->code_ptr);
        cemit_exit_tb(s, target);

        /* patch_stub1: */
        modify_br_off(patch_stub1, s->code_ptr);
    }

    switch (BITS(inst, 4, 4)) {
        case 0x1:
            /* bx rm */
            cemit_exit_tb_ind(s, ds->rm);
            break;
        case 0x2:
            /* bxj == bx */
            cemit_exit_tb_ind(s, ds->rm);
        case 0x3:
            /* blx rm */
            cemit_mov_i32(s, REG_LR, pc + 4);
            cemit_exit_tb_ind(s, ds->rm);
        default:
            abort();
            break;
    }

}

static int xlate_thumb2_br_imm(CPUARMState *env, TCGContext *s, decode_t *ds)
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

    inst = ds->inst;
    pc = ds->pc;
    target = pc + 8 + BITS(inst, 0, 24);
    tb = s->cur_tb;

    if (ds->cond == 0xf) {
        /*blx imm*/

        tb->may_change_state = 1;
        cemit_mov_i32(s, REG_LR, pc + 4);
        target = target | 0x1;
        cemit_exit_tb(s, target);// must change the cpu state

    } else {

        if (ds->cond != COND_AL) {
            patch_stub1 = s->code_ptr;
            /* (cond)b patch_stub1 */
            cemit_branch(s, ds->cond, s->code_ptr, NEED_PATCH); 

            target2 = ds->pc + 4;
            patch_stub2 = s->code_ptr;
            /* b patch_stub2 */
            cemit_branch(s, COND_AL, s->code_ptr, NEED_PATCH);
            /* patch_stub2: */
            modify_br_off(patch_stub2, s->code_ptr);
            cemit_exit_tb(s, target2);

            /* patch_stub1: */
            modify_br_off(patch_stub1, s->code_ptr);
        }

        if (BITS(inst, 24, 1) == 0x1) {
            /*bl imm*/
            cemit_mov_i32(s, REG_LR, pc + 4);
            cemit_exit_tb(s, target);
        } else {
            /*b imm*/
            cemit_exit_tb(s, target);
        }
    }
}

static int xlate_thumb2_datapro_reg(CPUARMState *env, TCGContext *s, decode_t *ds)
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
    uint32_t reg_free

    inst = ds->inst;
    
    if (inst & 0x0ff000f0 == 0x01600010) {
        /* clz rd, rm */
        Rd = BITS(inst, 12, 4);    
        rd_pos = 12;
        Rm = BITS(inst, 0, 4);
        reg_free = find_free_reg((1 << Rd) | (1 << Rm));
    } else if (inst & 0x0f9000f0 == 0x01000050) {
        /* qadd qsub qdadd qdsub */
        Rn = BITS(inst, 16, 4);    
        Rd = BITS(inst, 12, 4);    
        rd_pos = 12;
        Rm = BITS(inst, 0, 4);
        reg_free = find_free_reg((1 << Rd) | (1 << Rm) | (1 << Rn));
    } else if (inst & 0x0ff00090 == 0x01000080) {
        /* smul */
        Rn = BITS(inst, 12, 4);    
        Rd = BITS(inst, 16, 4);    
        rd_pos = 16;
        Rm = BITS(inst, 0, 4);
        Rs = BITS(inst, 8, 4);
        reg_free = find_free_reg((1 << Rd) | (1 << Rm) | (1 << Rn) | (1 << Rs));
    } else if (inst & 0x0f0000f0 == 0x00000090) {
        /* multiply */
        /* Fixme: Rn may be REG_PC. */
        Rn = BITS(inst, 12, 4);    
        Rd = BITS(inst, 16, 4);    
        rd_pos = 16;
        Rm = BITS(inst, 0, 4);
        Rs = BITS(inst, 8, 4);
        reg_free = find_free_reg((1 << Rd) | (1 << Rm) | (1 << Rn) | (1 << Rs));
    } else if (BITS(inst, 4, 1) == 0x0) {
        /*data_pro_imm_shift*/
        Rn = BITS(inst, 16, 4);
        Rd = BITS(inst, 12, 4);
        rd_pos = 12;
        Rm = BITS(inst, 0, 4);
        reg_free = find_free_reg((1 << Rd) | (1 << Rm) | (1 << Rn));
    } else if (BITS(inst, 4, 0) == 0x1) {
        /*data_pro_reg_shift*/
        Rn = BITS(inst, 16, 4);
        Rd = BITS(inst, 12, 4);
        rd_pos = 12;
        Rm = BITS(inst, 0, 4);
        Rs = BITS(inst, 8, 4);
        reg_free = find_free_reg((1 << Rd) | (1 << Rm) | (1 << Rn) | (1 << Rs));
    }

    if (Rd == REG_PC) {
        write_pc(s, ds, rd_pos, reg_free);
    } else {
        emit_normal(s, ds);
    }
}

static xlate_thumb2_datapro_imm(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    /* the type of correlated instructions is:
     * general data_pro_imm
     */

    uint32_t inst;
    uint32_t Rd, Rn;
    uint32_t rd_pos, reg_free;

    inst = ds->inst;
    Rd = BITS(inst, 12, 4);
    Rn = BITS(inst, 16, 4);
    rd_pos = 12;

    if (Rd == REG_PC) {
        reg_free = find_free_reg((1 << Rd) | (1 << Rn));
        write_pc(s, ds, rd_pos, reg_free);
    } else {
        emit_normal(s, ds);
    }
}

static xlate_thumb2_datatra_reg(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    /* the type of correlated instructions is:
     * extra ld/st
     * ld/st
     * muti ld/st
     */

    uint32_t inst;
    uint32_t index;
    uint32_t reg_free;

    inst = ds->inst;
    index = ds->index;
    Rd = BITS(inst, 12, 4);
    Rn = BITS(inst, 16, 4);
    Rm = BITS(inst, 0, 4);
    Rl = BITS(inst, 0, 15);


    /* Load/store doubleword.  */
    if (BITS(inst, 20, 1) == 0x1) {
        /* ldrd */
        if (rs == rd) {
            abort();
        } else {
            if (rd == REG_PC) {
                reg_free = find_free_reg((1 << rd) | (1 << rs));
                write_thumb2_pc(s, ds, 8, reg_free);
            } else if (rs == REG_PC) {
                reg_free = find_free_reg((1 << rd) | (1 << rs));
                write_thumb2_pc(s, ds, 12, reg_free);
            } else {
                cemit_thumb2_normal(s, ds);
            }
        }
    } else {
        /* strd */
        cemit_thumb2_normal(s, ds);
    }

}
static xlate_thumb2_datatra_imm(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    /* the type of correlated instructions is:
     * general ld/st imm offset
     */

    uint32_t inst;
    uint32_t index;
    uint32_t reg_free, rd_pos;

    inst = ds->inst;

    Rd = BITS(inst, 12, 4);
    Rn = BITS(inst, 16, 4);
    rd_pos =12;
    
    if (BITS(inst, 20, 1) == 0x1) {
        /* ld */
        if (Rd == REG_PC) {
            reg_free = find_free_reg((1 << Rn));
            write_pc(s, ds, rd_pos, reg_free);
        } else {
            emit_normal(s, ds);
        }

    } else {
        /* st */
        emit_normal(s, ds);
    }
}

static xlate_thumb2_statetra_reg(CPUARMState *env, TCGContext *s, decode_t *ds)
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
            emit_normal(s, ds);
        }
    } else {
        /*msr cpsr, rm*/
        tb->exit_tb_nopush = 1;
        cemit_exit_tb_msr(s, ds, Rm);
    }
}
static xlate_thumb2_statetra_imm(CPUARMState *env, TCGContext *s, decode_t *ds)
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

static int xlate_thumb2_exception(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    cemit_thumb2_normal(s, ds);
}

static int xlate_thumb2_coprocessor(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    cemit_thumb2_normal(s, ds);
}

void disas_thumb2_inst(CPUARMState *env, TCGContext *s, decode_t *ds, uint16_t inst_hw1)
{
    unsigned int cond, inst, val, op1, i, shift, rm, rs, rn, rd, sh;
    uint32_t arm_inst;
    uint32_t st_ld, pre_post, wb, dir;
    uint32_t reg_free;

    ds->pc += 2;
    inst = arm_lduw_code(env, ds->pc, ds->bswap_code);
    inst |= (uint32_t)insn_hw1 << 16;
    ds->inst = inst;

    if ((insn & 0xf800e800) != 0xf000e800) {
        ARCH(6T2);
    }

    rn = (insn >> 16) & 0xf;
    rs = (insn >> 12) & 0xf;
    rd = (insn >> 8) & 0xf;
    rm = insn & 0xf;

    switch (BITS(inst, 25, 4)) {
    case 0x0: case 0x1: case 0x2: case 0x3:
        /* 16-bit instructions.  Should never happen.  */
        abort();
    case 0x4:
        if (BITS(inst, 22, 1) == 0x1) {
            /* Other load/store, table branch.  */
            if (inst & 0x01200000) {
                ds->reglist = (1 << rs) | (1 << rd);
                ds->reg_src_pos = 16;
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

                ds->reg_src_pos = 16;
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
                ds->reg_src_pos = 16;
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
            case 0: /* Register controlled shift.  */
                ds->func = xlate_thumb2_datapro_reg;
                break;
            case 1: /* Sign/zero extend.  */
                ds->func = xlate_thumb2_datapro_reg;
                break;
            case 2: /* SIMD add/subtract.  */
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
            if (insn & 0x5000) {
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
                            ds->func = xlate_nop;
                            break;
                        }
                        /* Implemented as NOP in user mode.  */
                        if (IS_USER(s)) {
                            ds->func = xlate_nop;
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
                            ds->func = xlate_nop;
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
                        tmp = tcg_temp_new_i32();
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
                op = (insn >> 22) & 0xf;
                /* Generate a conditional jump to next instruction.  */
                ds->func = xlate_thumb2_br_imm;
            }
        } else {
            /* Data processing immediate.  */
            if (inst & (1 << 25)) {
                if (inst & (1 << 24)) {
                    if (inst & (1 << 20))
                        abort();
                    /* Bitfield/Saturate.  */
                    ds->func = xlate_thumb2_datapro_imm;
                } else {
                    ds->func = xlate_thumb2_datapro_imm;
                }
            } else {
                /* modified 12-bit immediate.  */
                ds->func = xlate_thumb2_datapro_imm;
            }
        }
        break;
    case 12: /* Load/store single data item.  */
        ds->func = xlate_thumb2_datapro_imm;
        break;
    default:
        abort();
    }

}
void disas_thumb_inst(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    unsigned int cond, inst, val, op1, i, shift, rm, rs, rn, rd, sh;


    /* should be handled later */
    if (ds->condexec_mask) {
        cond = ds->condexec_cond;
        if (cond != COND_AL) {
            ds->condmp = 1;
        }
    }

    inst = arm_lduw_code(env, ds->pc, ds->bswap_code);
    ds->inst = inst;
    ds->index = BITS(inst, 13, 3);

    switch (ds->index) {
        case 0x0:
            switch (BITS(inst, 11, 2)) {
                case 0x0:
                case 0x1:
                case 0x2:
                    xlate_thumb_datapro_reg(env, s, ds);
                    break;
                case 0x3:
                    if (BITS(inst, 10, 1) == 0x0) {
                        xlate_thumb_datapro_reg(env, s, ds);
                    } else {
                        xlate_thumb_datapro_imm(env, s, ds);
                    }
            }
            break;
        case 0x1:
            xlate_thumb_datapro_imm(env, s, ds);
            break;

        case 0x2:
            if (BITS(inst, 12, 1) == 0x1) {
                /* ld/st reg offset */
            } else {
                if (BITS(inst, 11, 1) == 0x1) {
                    /* ld from literal pool */
                } else {
                    if (BITS(inst, 10, 1) == 0x0) {
                        /* data-pro reg */
                    } else {
                        if (BITS(inst, 8, 3) == 0x7) {
                            /* br/ex */
                        } else {
                            /* special data pro */
                        }
                    }
                }
            }
            break;
        case 0x3:
            /* ld/st word/byte imm off */
            xlate_thumb_datatra_imm(env, s, ds);
            break;
        case 0x4:
            if (BITS(inst, 12, 1) == 0x1) {
                /* ld/st halfword imm off */
            } else {
                /* ld/st stack */
            }
            break;
        case 0x5:
            if (BITS(inst, 12, 1) == 0x0) {
                /* add to sp or pc */
            } else {
                /* miscellaneous inst */
            }
            break;
        case 0x6:
            if (BITS(inst, 12, 1) == 0x0) {
                /* ld/st multiple */
            } else if (BITS(inst, 8, 4) == 0xe) {
                /* undefined instructions */
            } else if (BITS(inst, 8, 4) == 0xf) {
                /* service call */
            } else {
                /* conditional branch */
            }
            break;
        case 0x7:
            if (BITS(inst, 12, 1) == 0x1) {
                disas_thumb2_inst(env, s, ds);
            } else {
                if (BITS(inst, 11, 1) == 0x1) {
                    disas_thumb2_inst(env, s, ds, inst);
                } else {
                    /* unconditional branch */
                }
            }
            break;
        default :
            break;
    }
}
