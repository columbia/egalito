#ifndef EGALITO_CONFIG_AARCH64_UBUNTU_H
#define EGALITO_CONFIG_AARCH64_UBUNTU_H

/* For Ubuntu on AARCH64 */

/* common */

/* src */

#define USR_LIB_DEBUG_BY_NAME
#define CACHE_DIR "_cache"
#define SANDBOX_BASE_ADDRESS    0x40000000

/* app */

#define PROMPT_COLOR    C_GREEN

/* test */

#define ANALYSIS_JUMPTABLE_MAIN_COUNT               1
#define ANALYSIS_JUMPTABLE_PARSE_EXPRESSION_COUNT   2

#define PASS_STACKEXTEND_RESTORE_SP_FROM_X29        1

#endif
