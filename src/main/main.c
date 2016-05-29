#include <stdio.h>
#include "main.h"

#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"

int main() {
    csh handle;
    cs_insn *insn;
    const uint8_t *code = (uint8_t *)CODE;

    if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return -1;
    }

    // switch to AT&T syntax
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

    size_t count = cs_disasm(handle, code, sizeof(CODE)-1, 0x1000, 0, &insn);
    if(count > 0) {
        for(size_t j = 0; j < count; j++) {
            printf("0x%08lx:\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
                    insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else printf("ERROR: Failed to disassemble given code!\n");

    cs_close(&handle);
    return 0;
}
