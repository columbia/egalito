#ifndef EGALITO_CONFIG_X86_64_GENTOO_H
#define EGALITO_CONFIG_X86_64_GENTOO_H

/* For Gentoo on X86_64 */

/* common */

/* src */

#define USR_LIB_DEBUG_BY_NAME
#define SANDBOX_BASE_ADDRESS    0x40000000

/* app */

#define PROMPT_COLOR    C_WHITE

/* test */

#define ANALYSIS_JUMPTABLE_MAIN_COUNT               1
#define ANALYSIS_JUMPTABLE_PARSE_EXPRESSION_COUNT   2

#endif
