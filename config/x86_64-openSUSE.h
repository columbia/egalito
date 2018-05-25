#ifndef EGALITO_CONFIG_X86_64_OPENSUSE_H
#define EGALITO_CONFIG_X86_64_OPENSUSE_H

/* For openSUSE tumbleweed on X86_64 */

/* common */

/* src */

#define HAVE_EXPLICIT_BZERO
#define SANDBOX_BASE_ADDRESS    0x40000000
#define JIT_TABLE_SIZE          64 * 0x1000 // must fit in 32-bit
//#define JIT_RESET_THRESHOLD     10000

/* app */

#define PROMPT_COLOR    C_GREEN

/* test */

#define ANALYSIS_JUMPTABLE_MAIN_COUNT               1
#define ANALYSIS_JUMPTABLE_PARSE_EXPRESSION_COUNT   2

#endif
