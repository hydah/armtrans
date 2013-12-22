
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



