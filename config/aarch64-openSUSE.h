#ifndef EGALITO_CONFIG_AARCH64_OPENSUSE_H
#define EGALITO_CONFIG_AARCH64_OPENSUSE_H

/* For openSUSE on AARCH64 */

/* common */

/* src */

#define CACHE_DIR "_cache"
#define SANDBOX_BASE_ADDRESS    0x40000000
#define JIT_TABLE_SIZE          64 * 0x1000 // must fit in 32-bit

/* app */

#define PROMPT_COLOR    C_GREEN

/* test */

#if defined(__GNUC__) && (__GNUC__ >= 7)    /* tumbleweed */
#define ANALYSIS_JUMPTABLE_MAIN_COUNT               0
#define ANALYSIS_JUMPTABLE_PARSE_EXPRESSION_COUNT   1
#else
#define ANALYSIS_JUMPTABLE_MAIN_COUNT               1
#define ANALYSIS_JUMPTABLE_PARSE_EXPRESSION_COUNT   2
#endif

#if defined(__GNUC__) && (__GNUC__ >= 7)    /* tumbleweed */
#define PASS_STACKEXTEND_RESTORE_SP_FROM_X29        0
#else   /* gcc-6 */
#define PASS_STACKEXTEND_RESTORE_SP_FROM_X29        1
#endif
#endif
