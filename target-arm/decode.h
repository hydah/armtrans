#ifndef __DECODE_H__
#define __DECODE_H__

#include <stdbool.h>
#include "cpu.h"
typedef struct reg_desc reg_desc;
struct reg_desc {
    uint32_t reg;
    uint32_t reg_pos;
};
enum INST_TYPE {
    ARM_INST = 1,
    THUMB_INST,
    THUMB2_INST,
};

typedef struct decode_s decode_t;
struct decode_s {
    uint32_t index;
    uint32_t cond;
	uint32_t op;
    uint32_t inst;

	uint32_t a; /* op */
	uint32_t P;
	uint32_t U;
	uint32_t B;
	uint32_t W;
	uint32_t A;
	uint32_t L;
	uint32_t S;
	uint32_t Rh;
	uint32_t Rc;
    uint32_t t;
    uint32_t r;
    uint32_t b;
    uint32_t off;
    uint32_t p;
    uint32_t q;

    bool bswap_code;
    uint8_t *pc;
    int (*func)(CPUARMState *env, TCGContext *s, decode_t *ds);
    bool is_jmp;
    uint32_t src_regpos_list;
    uint32_t dst_regpos_list;

    reg_desc reg_src[4];
    reg_desc reg_dst[4];

    int Rd, Rd_pos;
    int Rd2, Rd2_pos;
    int Rm, Rm_pos;
    int Rn, Rn_pos;
    int Rs, Rs_pos;
	uint32_t Rl; /* RegList for multi ld/st */
    uint32_t rd_num;
    uint32_t rs_num;
    uint32_t reg_list;
    int inst_type;
};

enum OP_NAME {
	OP_AND = 0,
	OP_EOR,
	OP_SUB,
	OP_RSB,
	OP_ADD,
	OP_ADC,
	OP_SBC,
	OP_RSC,
	OP_TST,
	OP_TEQ,
	OP_CMP,
	OP_CMN,
	OP_ORR,
	OP_MOV,
	OP_BIC,
	OP_MVN,
}; 

enum REG_NAME {
	REG_R0 = 0,
	REG_R1,
	REG_R2,
	REG_R3,
	REG_R4,
	REG_R5,
	REG_R6,
	REG_R7,
	REG_R8,
	REG_R9,
	REG_R10,
	REG_FP,
	REG_IP,
	REG_SP,
	REG_LR,
	REG_PC = 15,
    REG_NA = 0xdeadbeaf,
};

#define REG_NUM		16

int do_decode(Inst *pc, decode_t *ds);
bool emit_branch(TCGContext *s, decode_t *ds);
bool emit_normal(TCGContext *s, decode_t *ds);
bool emit_exception(TCGContext *s, decode_t *ds);
bool emit_null(TCGContext *s, decode_t *ds);
bool emit_br_ind(TCGContext *s, decode_t *ds);
int disas_insn(Inst *pc, decode_t *ds);

#ifdef DEBUG_AT
    #define AT_DBG(...) fprintf(stderr, __VA_ARGS__);
#else
    #define AT_DBG(...) ((void )0);
#endif

#define AT_ERR(...) do { \
	fprintf(stderr, "%s:%d:  ", __func__, __LINE__); \
	fprintf(stderr, __VA_ARGS__); \
}while(0);

#define BITS(v, start, n) (((v) >> (start)) & ((1 << (n)) - 1))
#define CLR_BITS(v, start, n) ((v) & (~(((1 << (n)) - 1) << (start))))

#endif

