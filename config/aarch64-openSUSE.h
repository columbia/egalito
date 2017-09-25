#ifndef EGALITO_CONFIG_AARCH64_OPENSUSE_H
#define EGALITO_CONFIG_AARCH64_OPENSUSE_H

/* For openSUSE tumbleweed on AARCH64 */

/* common */

/* src */

#define USR_LIB_DEBUG_BY_NAME
#define CACHE_DIR "_cache"
#define SANDBOX_BASE_ADDRESS    0x80000000

/* app */

#define PROMPT_COLOR    C_GREEN

/* test: use gcc-7 if on Leap42.3 */

#define ANALYSIS_JUMPTABLE_MAIN_COUNT               0
#define ANALYSIS_JUMPTABLE_PARSE_EXPRESSION_COUNT   1

#endif
