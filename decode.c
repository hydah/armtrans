#include <stdint.h>
#include <stdio.h>
#include "decode.h"
#include "emit.h"

static const char *act[] = {
	"AND",
	"EOR",
	"SUB",
	"RSB",
	"ADD",
	"ADC",
	"SBC",
	"RSC",
	"TST",
	"TEQ",
	"CMP",
	"CMN",
	"ORR",
	"MOV",
	"BIC",
	"MVN",
}; 

static int swap(Inst inst, decode_t *ds)
{
	ds->B = BITS(inst, 22, 1);
	ds->Rn = BITS(inst, 16, 4);
	ds->Rd = BITS(inst, 12, 4);
	ds->Rm = BITS(inst, 0, 4);

	ds->fun = emit_normal;

	AT_DBG("swap : %x %x %x %x\n",ds->B, ds->Rn, ds->Rd, ds->Rm);
	return 0;
}

static int mult(Inst inst, decode_t *ds)
{
	ds->A = BITS(inst, 21, 1);
	ds->S = BITS(inst, 20, 1);
	ds->Rd = BITS(inst, 16, 4);
	ds->Rn = BITS(inst, 12, 4);
	ds->Rs = BITS(inst, 8, 4);
	ds->Rm = BITS(inst, 0, 4);
	
	if(ds->Rd == ds->Rm) {
		AT_DBG("mult Rd==Rm error\n");
		return 1;
	}

	if((ds->Rd == REG_PC) || (ds->Rm == REG_PC) || 
	   (ds->Rs == REG_PC) || (ds->Rn == REG_PC)) {
		AT_DBG("mult use R15 error\n");return 1;
	}

	ds->fun = emit_normal;

	AT_DBG("mult : %x %x %x %x %x %x\n",ds->A, ds->S, ds->Rd, ds->Rn, ds->Rs, ds->Rm);
	return 0;
}

static int longmult(Inst inst, decode_t *ds)
{
	ds->U = BITS(inst, 22, 1);
	ds->A = BITS(inst, 21, 1);
	ds->S = BITS(inst, 20, 1);
	ds->Rd = BITS(inst, 16, 4);
	ds->Rn = BITS(inst, 12, 4);
	ds->Rs = BITS(inst, 8, 4);
	ds->Rm = BITS(inst, 0, 4);

	if(ds->Rh == ds->Rm) {AT_DBG("longmult Rh==Rm error\n");return 1;}
	if(ds->Rh == ds->Rl) {AT_DBG("longmult Rh==Rl error\n");return 1;}
	if(ds->Rl == ds->Rm) {AT_DBG("longmult Rl==Rm error\n");return 1;}

	if((ds->Rd == REG_PC) || (ds->Rm == REG_PC) || 
	   (ds->Rs == REG_PC) || (ds->Rn == REG_PC)) {
		AT_DBG("longmult use R15 error\n");return 1;
	}

	ds->fun = emit_normal;

	AT_DBG("longmult : %x %x %x %x %x %x %x\n",ds->U, ds->A, ds->S, ds->Rh, ds->Rl, ds->Rs, ds->Rm);
	return 0;
}

static int msr_mrs(Inst inst, decode_t *ds)
{
	ds->fun = emit_exception;

	AT_DBG("msr_mrs do nth\n");
	return 0;
}

static void out_t(uint32_t c, uint32_t t)
{
	switch(t)
	{
		case 0:
			AT_DBG("LSL c:%x\n",c);
			break;
		case 1:
			AT_DBG("LSL Rc:%x\n",c>>1);
			break;
		case 2:
			AT_DBG("LSR c:%x\n",c);
			break;
		case 3:
			AT_DBG("LSR Rc:%x\n",c>>1);
			break;
		case 4:
			AT_DBG("ASR c:%x\n",c);
			break;
		case 5:
			AT_DBG("ASR Rc:%x\n",c>>1);
			break;
		case 6:
			AT_DBG("ROR c:%x\n",c);
			break;
		case 7:
			AT_DBG("ROR Rc:%x\n",c>>1);
			break;
		default :;
	}
}

static int reg_data_pro(Inst inst, decode_t *ds)
{
	if((BITS(inst, 4, 4) == 0x9) && (BITS(inst, 23, 4) == 0x1)) {
		return longmult(inst, ds);
	}

	if((BITS(inst, 4, 4) == 0x9) && (BITS(inst, 22, 5) == 0x0)) {
		return mult(inst, ds);
	}

	if((BITS(inst, 4, 8) == 0x9) && (BITS(inst, 20, 2) == 0x0) && 
	   (BITS(inst, 23, 5) == 0x2)) {
		return swap(inst, ds);
	}

	if((inst & 0x0fb0fff0) == 0x0120f000) {
		return msr_mrs(inst, ds);
	}
	if((inst & 0x0fbf0fff) == 0x010f0000) {
		return msr_mrs(inst, ds);
	}
	if((inst & 0x0f000090) == 0x01000090) {
		AT_ERR("undefine 1\n");
		return 0;
	}

	ds->a = BITS(inst, 21, 4);
	ds->S = BITS(inst, 20 ,1);
	ds->Rn = BITS(inst, 16, 4);
	ds->Rd = BITS(inst, 12 ,4);
	ds->Rc = BITS(inst, 7, 5);
	ds->t = BITS(inst, 4 ,3);
	ds->Rm = BITS(inst, 0 ,4);

	if(((ds->a == OP_TST) || (ds->a == OP_TEQ) || (ds->a == OP_CMP) || 
            (ds->a == OP_CMN)) && (ds->Rd != 0x0)) {
		AT_ERR("reg Rd error\n");
		return 1;
	}

	if(((ds->a == OP_MOV) || (ds->a == OP_MVN)) && (ds->Rn != 0x0)) {
		AT_ERR("reg Rn error\n");
		return 1;
	}

	if((BITS(ds->t, 0, 1) == 0x1) && (BITS(inst, 7, 1) == 0x1)) {
		AT_ERR("reg Rc error: %p:0x%x\n", ds->pc, inst); /* FIXME: not a error,just unfinished; */
                ds->fun = emit_normal;
		return 1;
	}

        if(ds->Rd == REG_PC) ds->fun = emit_br_ind;
	else ds->fun = emit_normal;

	AT_DBG("reg_data_pro : %s Rn:%x Rd:%x Rm:%x S:%x ",act[ds->a], ds->Rn, ds->Rd, ds->Rm, ds->S);
	out_t(ds->Rc,ds->t);
	return 0;
}

static int imd_data_pro(Inst inst, decode_t *ds)
{
	if((inst & 0x0fb0f000) == 0x0320f000) {
		return msr_mrs(inst, ds);
	}
	
	ds->a = BITS(inst, 21, 4);
	ds->S = BITS(inst, 20 ,1);
	ds->Rn = BITS(inst, 16, 4);
	ds->Rd = BITS(inst, 12 ,4);
	ds->r = BITS(inst, 8, 4);
	ds->b = BITS(inst, 0, 8);

	if(((ds->a == OP_TST) || (ds->a == OP_TEQ) || (ds->a == OP_CMP) || 
            (ds->a == OP_CMN)) && (ds->Rd != 0x0)) {
		AT_DBG("reg Rd error\n");
		return 1;
	}

	if(((ds->a == OP_MOV) || (ds->a == OP_MVN )) && (ds->Rn != 0x0)) {
		AT_DBG("reg Rn error\n");
		return 1;
	}

        if(ds->Rd == REG_PC) ds->fun = emit_br_ind;
	else ds->fun = emit_normal;

	AT_DBG("imd_data_pro : %s Rn:%x Rd:%x S:%x r:%x b:%x\n",act[ds->a], ds->Rn, ds->Rd, ds->S, ds->r, ds->b);
	return 0;
}

static int imd_data_tra(Inst inst, decode_t *ds)
{
	ds->P = BITS(inst, 24, 1);
	ds->U = BITS(inst, 23, 1);
	ds->B = BITS(inst, 22, 1);
	ds->W = BITS(inst, 21, 1);
	ds->L = BITS(inst, 20, 1);
	ds->Rn = BITS(inst, 16, 4);
	ds->Rd = BITS(inst, 12, 4);
	ds->off = BITS(inst, 0, 8);

        if(ds->Rd == REG_PC) ds->fun = emit_br_ind;
	else ds->fun = emit_normal;

	AT_DBG("imd_data_tra : P:%x U:%x B:%x W:%x L:%x Rn:%x Rd:%x o:%x\n",ds->P, ds->U, ds->B, ds->W, ds->L, ds->Rn, ds->Rd, ds->off);

	return 0;
}

static int reg_data_tra(Inst inst, decode_t *ds)
{
	if(BITS(inst, 4 ,1) == 0x1) {
		AT_DBG("undefine 2\n");return 1;
	}

	ds->P = BITS(inst, 24, 1);
	ds->U = BITS(inst, 23, 1);
	ds->B = BITS(inst, 22, 1);
	ds->W = BITS(inst, 21, 1);
	ds->L = BITS(inst, 20, 1);
	ds->Rn = BITS(inst, 16, 4);
	ds->Rd = BITS(inst, 12, 4);
	ds->Rc = BITS(inst, 7, 5);
	ds->t = BITS(inst, 5, 2);
	ds->Rm = BITS(inst, 0, 4);

        if(ds->Rd == REG_PC) ds->fun = emit_br_ind;
	else ds->fun = emit_normal;

	AT_DBG("reg_data_tra : P:%x U:%x B:%x W:%x L:%x Rn:%x Rd:%x Rm:%x ",ds->P, ds->U, ds->B, ds->W, ds->L, ds->Rn, ds->Rd,  ds->Rm);
	out_t(ds->Rc, ds->t);

	return 0;
}

static int co_mrc_mcr(Inst inst, decode_t *ds)
{
	ds->fun = emit_exception;

	AT_DBG("co_mrc_mcr do nth\n");
	return 0;
}

static int co_ldc_stc(Inst inst, decode_t *ds)
{
	ds->fun = emit_exception;

	AT_DBG("co_ldc_stc do nth\n");
	return 0;
}

static int soft_inter(Inst inst, decode_t *ds)
{
	ds->fun = emit_exception;

	AT_DBG("soft_inter do nth\n");
	return 0;
}

static int co_data_pro(Inst inst, decode_t *ds)
{
	if(BITS(inst, 24, 1) == 0x1) return soft_inter(inst, ds);
	if(BITS(inst, 4, 1) == 0x1) return co_mrc_mcr(inst, ds);

	ds->off = BITS(inst, 20, 4);
	ds->Rn = BITS(inst, 16, 4);
	ds->Rd = BITS(inst, 12, 4);
	ds->p = BITS(inst, 8, 4);
	ds->q = BITS(inst, 5, 3);
	ds->Rm = BITS(inst, 0, 4);

        ds->fun = emit_exception;

	AT_DBG("co_data_pro : %x %x %x %x %x %x\n",ds->off, ds->Rn, ds->Rd, ds->p, ds->q, ds->Rm);
	return 0;
}

static int blk_data_tra(Inst inst, decode_t *ds)
{
	ds->P = BITS(inst, 24, 1);
	ds->U = BITS(inst, 23, 1);
	ds->B = BITS(inst, 22, 1);
	ds->W = BITS(inst, 21, 1);
	ds->L = BITS(inst, 20, 1);
	ds->Rn = BITS(inst, 16, 4);
	ds->Rl = BITS(inst, 0, 16);

        if(BITS(ds->Rl, REG_PC, 1) == 0x1) {
		ds->fun = emit_br_ind;
	} else {
		ds->fun = emit_normal;
	}

	AT_DBG("blk_data_tra : P:%x U:%x S:%x W:%x L:%x Rn:%x Rl:%x\n",ds->P, ds->U, ds->S, ds->W, ds->L, ds->Rn, ds->Rl);
	return 0;
}

static int branch(Inst inst, decode_t *ds)
{
	ds->L = BITS(inst, 24, 1);
	ds->off = BITS(inst, 0, 24);

	ds->fun = emit_branch;

	AT_DBG(stderr, "branch\n");
	return 0;
}

static void ds_init(decode_t *ds, Inst *pc)
{
        Inst inst;

        inst = *pc;

        ds->pc = pc;
	ds->cond = BITS(inst, 28, 4);
	ds->op = BITS(inst, 25, 3);

        /* init field */
        ds->fun = emit_null;
        ds->Rn = REG_NA;
        ds->Rd = REG_NA;
        ds->Rm = REG_NA;
        ds->Rl = REG_NA;
}

static int (*decode_fun[8])(Inst, decode_t *) = {
	reg_data_pro,
	imd_data_pro, 
	imd_data_tra, 
	reg_data_tra, 
	blk_data_tra,
	branch, 
	co_ldc_stc, 
	co_data_pro,
};

int do_decode(Inst *pc, decode_t *ds)
{
        Inst inst;
	int ret;

        if(pc > (Inst *)0xffff0000) {
		ds->pc = pc;
        	ds->fun = emit_exception;
		return 0;
	}

        ds_init(ds, pc);

	inst = *pc;

	ret = decode_fun[ds->op](inst, ds);

	if(ds->fun == emit_null) {
		AT_ERR("op=0x%x inst=0x%x pc=%p\n", ds->op, inst, pc);
	}

	return ret;
}

