#ifndef EGALITO_CONFIG_X86_64_DEBIAN_H
#define EGALITO_CONFIG_X86_64_DEBIAN_H

/* For Debian testing (buster) on riscv */

/* common */

/* src */

#define SANDBOX_BASE_ADDRESS    0x40000000
#define JIT_TABLE_SIZE          64 * 0x1000 // must fit in 32-bit

/* app */

#define PROMPT_COLOR    C_WHITE

/* test */

#endif
