#ifndef __EMIT_H_
#define __EMIT_H_


#define NEED_PATCH_64   0x5a5a5a5a5a5a5a5a
#define NEED_PATCH_32   0x5a5a5a5a
#define NEED_PATCH_8    0x5a
#define MAX_INSNS       1024 * 8


#define code_emit32(code_emit_ptr, val) do{ \
        *(uint32_t *)(code_emit_ptr) = (val); \
        (code_emit_ptr) += 4; \
} while(0)

#endif

