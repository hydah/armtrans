#include "decode.h"

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

static int write_pc(TCGContext *s, decode_t *ds, uint32_t rd_pos, uint32_t reg_free)
{
    uint32_t inst;
    uint32_t *patch_stub1, *patch_stub2;

    inst = ds->inst;
    inst = inst & ~(0xf << rd_pos) | (reg_free << rd_pos);

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

    cemit_push(reg_free);
    code_emit32(s->code_ptr, inst);
    cemit_exit_tb_ind(s, reg_free);
}

static int disas_branch_reg(CPUARMState *env, TCGContext *s, decode_t *ds)
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

static int disas_branch_imm(CPUARMState *env, TCGContext *s, decode_t *ds)
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

static int disas_data_pro_reg(CPUARMState *env, TCGContext *s, decode_t *ds)
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

static disas_data_pro_imm(CPUARMState *env, TCGContext *s, decode_t *ds)
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

static disas_data_tra_reg(CPUARMState *env, TCGContext *s, decode_t *ds)
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

    if(index == 0x0) {
        /* extra ld/st */
        if (inst & 0xc0 == 0xc0 && BITS(inst, 20, 1) == 0x1) {
            /* ld */
            if (Rd == REG_PC) {
                reg_free = find_free_reg((1 << Rd) | (1 << Rn));
                write_pc(s, ds, rd_pos, reg_free);
            } else {
                emit_normal(s, ds);
            }
        } else if (inst & 0xf0 == 0xf0 &&) {
            /* ld double */
            if (Rd == REG_LR) {
                AT_DBG(" ld double. Rd cannot be lr\n");
                abort();
            } else {
                emit_normal(s, ds);
            }
        } else if (BITS(inst, 20, 1) == 0x1) {
            /* ld */
            if (Rd == REG_PC) {
                reg_free = find_free_reg((1 << Rd) | (1 << Rn) | (1 << Rm));
                write_pc(s, ds, rd_pos, reg_free);
            } else {
                emit_normal(s, ds);
            }
        } else {
            /* st */
            emit_normal(s, ds);
        }
    } else if (index == 0x3) {
        /* ld/st reg */
        if (BITS(inst, 20, 1) == 0x1) {
            /* ld */
            ds->cur_tb->may_change_state = 1;
            if (Rd == REG_PC) {
                reg_free = find_free_reg((1 << Rd) | (1 << Rn) | (1 << Rm));
                write_pc(s, ds, rd_pos, reg_free);
            } else {
                emit_normal(s, ds);
            }
        } else {
            emit_normal(s, ds);
        }
    } else if (index == 0x4) {
        /* muti ld/st */
        if (BITS(inst, 20, 1) == 0x1) {
            /* ldm */
            if (BITS(Rl, 14, 1) == 0x1) {

                uint32_t *patch_stub1, *patch_stub2;

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

                code_emit32(s->code_ptr, (inst & ~(1 << 14)));
                reg_free = find_free_reg((1 << Rn));
                cemit_push(s, reg_free);
                code_emit32(s->code_ptr, (inst & ~((1 << 15) - 1) | (1 << reg_free)));
                cemit_exit_tb_ind(s, reg_free);
            } else {
                emit_normal(s, ds);
            }
        } else {
            emit_normal(s, ds);
        }

    }

}
static disas_data_tra_imm(CPUARMState *env, TCGContext *s, decode_t *ds)
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

static disas_state_tra_reg(CPUARMState *env, TCGContext *s, decode_t *ds)
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
static disas_state_tra_imm(CPUARMState *env, TCGContext *s, decode_t *ds)
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

static disas_exception(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    emit_normal(s, ds);
}

static disas_coprocessor(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    emit_normal(s, ds);
}

void disas_arm_inst(CPUARMState *env, TCGContext *s, decode_t *ds)
{
    unsigned int cond, inst, val, op1, i, shift, rm, rs, rn, rd, sh;

    inst = arm_ldl_code(env, s->pc, s->bswap_code);
    ds->inst = inst;
    ds->cond = BITS(inst, 28, 4);
    ds->index = BITS(inst, 25, 3);
    ds->op = BITS(inst, 21, 4);
    ds->type = 0; // DATA_PRO_IMM; DATA_PRO_REG; DATA_TRAN_IMM; DATA_TRAN_REG; BRANCH; MEM_ACCESS; COPROCESSOR; EXCEPTION;

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
                if ((insn & 0x0ff10020) == 0x01000000) {
                    /* cps (privileged) */
                    if (IS_USER(s))
                        return;
                    else
                        abort();
                } else if ((insn & 0x0ffffdff) == 0x01010000) { 
                    ARCH(6);
                    /* setend */
                    if (((insn >> 9) & 1) != ds->bswap_code) { 
                        /* Dynamic endianness switching not implemented. */
                        abort();
                    }
                    return;
                }
                break;
            case 0x1:
                abort();
                break;
            case 0x2:
            case 0x3:
                /* pld */
                if (((insn & 0x0f30f000) == 0x0510f000) ||
                        ((insn & 0x0f30f010) == 0x0710f000)) {
                    if ((insn & (1 << 22)) == 0) {
                        /* PLDW; v7MP */
                        if (!arm_feature(env, ARM_FEATURE_V7MP)) {
                            goto illegal_op;
                        }
                    }
                    /* Otherwise PLD; v5TE+ */
                    ARCH(5TE);
                    return;
                }
                break;
            case 0x4:
                if ((insn & 0x0e5fffe0) == 0x084d0500) { 
                    /* srs */ 
                    if (IS_USER(s))
                        goto illegal_op;
                    ARCH(6);
                } else if ((insn & 0x0e50ffe0) == 0x08100a00) {
                    /* rfe */
                    if (IS_USER(s))
                        goto illegal_op;
                    ARCH(6);
                }
                break;
            case 0x5:
                if ((insn & 0x0e000000) == 0x0a000000) {
                    /* blx imm */
                    ds->func = disas_branch_imm;
                } else {
                    abort();
                }
                break;
            case 0x6:
                if ((insn & 0x0fe00000) == 0x0c400000) {
                    /* Coprocessor double register transfer.  */
                    ARCH(5TE);
                }
                break;
            case 0x7:
                if ((insn & 0x0f000010) == 0x0e000010) {
                    /* Additional coprocessor register transfer.  */
                } else {
                    /* Undefined instruction */
                    abort();
                }
                break;
            default :
                break;
        }
    }

    if (ds->cond != 0xe) {
        /* if not always execute, we generate a conditional jump to
           next instruction */
        ds->condlabel = gen_new_label();
        gen_test_cc(ds->cond ^ 1, ds->condlabel);
        ds->condjmp = 1;
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
                            ds->func = disas_state_tra_reg;
                        } else {
                            /*msr cpsr, rd*/
                            ds->func = disas_state_tra_reg;
                        }
                        break;
                    case 0x1:
                        if (BITS(inst, 21, 2) == 0x1) {
                            /*bx rm*/
                            ds->func = disas_branch_reg;
                        }else if(BITS(inst, 21, 2) == 0x3) {
                            /*clz rm*/
                            ds->func = disas_data_pro_reg;
                        } else {
                            abort();
                        }
                        break;
                    case 0x2:
                        if (BITS(inst, 21, 2) == 0x1) {
                            /*bxj rm*/
                            ds->func = disas_branch_reg;
                        } else {
                            abort();
                        }
                        break;
                    case 0x3:
                        if (BITS(inst, 21, 2) == 0x1) {
                            /*blx rm*/
                            ds->func = disas_branch_reg;
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
                                ds->func = disas_data_pro_reg;
                            default:
                                break;
                        }
                    case 0x7:
                        if (BITS(inst, 21, 2) == 0x1) {
                            /*bkpt imm*/
                            ds->func = disas_exception;
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
                                    ds->func = disas_data_pro_reg;

                                default:
                                    abort();
                        }
                        break;
                    default:
                        abort();
                } /*end of switch*/
            } else if (BITS(inst, 24, 1) == 0x0 && BITS(inst, 4, 4) == 0x9) {
                /*multiply instructions*/
                ds->func = disas_data_pro_reg;
            } else if (BITS(inst, 7, 1) == 0x1 && BITS(inst, 4, 1) == 0x1) {
                /*extra load/store inst*/
                ds->func = disas_data_tra_reg;
            } else if (BITS(inst, 4, 1) == 0x0) {
                /*data_pro_imm_shift*/
                ds->func = disas_data_pro_reg;
            } else if (BITS(inst, 4, 0) == 0x1) {
                /*data_pro_reg_shift*/
                ds->func = disas_data_pro_reg;
            } else {
                abort();
            }
            
        case 0x1:
            if (BITS(inst, 23, 2) == 0x2 && BITS(inst, 20, 2) == 0x2) {
                /*msr cpsr, imm */
                ds->func = disas_state_tra_imm;
            } else if(BITS(inst, 23, 2) == 0x2 && BITS(inst, 20, 2) == 0x0) {
                abort();
            } else {
                /*data_pro_imm*/
                ds->func = disas_data_pro_imm;
            }

            break;

        case 0x2:
            /*ld/st imm*/
            ds->func = disas_data_tra_imm;
            break;    
        case 0x3:
            if (BITS(inst, 4, 1) == 0x0) {
                /*ld/st reg*/
                ds->func = disas_data_tra_reg;
            } else {
                /*media inst*/
                /*architecturally undefined*/
            }

            break;
        case 0x4:
            /*ld/st mutiple*/
            ds->func = disas_data_tra_reg;
            break;
        case 0x5:
            /*b/bl*/
            ds->func = disas_branch_imm;
        case 0x6:
            /*coprocessor*/
            ds->func = disas_coprocessor;
        case 0x7:
            if (BITS(inst, 24, 1) == 0x1) {
                /*swi*/
                ds->func = disas_exception;
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
}
