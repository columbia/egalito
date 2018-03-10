#ifndef EGALITO_CONFIG_X86_64_DEVUAN_H
#define EGALITO_CONFIG_X86_64_DEVUAN_H

/* For Debian testing (buster) on X86_64 */

/* common */

/* src */

#define USR_LIB_DEBUG_BY_HASH
#define SANDBOX_BASE_ADDRESS    0x40000000
#define JIT_TABLE_SIZE          64 * 0x1000 // must fit in 32-bit

/* app */

#define PROMPT_COLOR    C_WHITE

/* test */

#define ANALYSIS_JUMPTABLE_MAIN_COUNT               1
#define ANALYSIS_JUMPTABLE_PARSE_EXPRESSION_COUNT   2

#endif
