#include "libchacks.h"
#include "operation/find2.h"
#include "operation/mutator.h"
#include "disasm/disassemble.h"
#include "pass/switchcontext.h"
#include "instr/concrete.h"
#include "log/log.h"

// This is used to make IFUNCs obey calling conventions. Normally, they
// overwrite whatever registers they like. We save all callee-saved registers
// except the return value %rax, which is set to the target function address.

void LibcHacksPass::visit(Module *module) {
#ifdef ARCH_X86_64
    const char *funcs[] = {
        "memcpy", "mempcpy",
        "memmove", "__memmove_chk", "memchr", "memset",
        "strcmp", "strncmp", "strcpy", "strncpy",
        "strchr"
    };

    for(size_t i = 0; i < sizeof(funcs)/sizeof(*funcs); i ++) {
        auto func = ChunkFind2(program).findFunction(funcs[i]);
        if(func) fixFunction(func);
    }
#endif
}

void LibcHacksPass::fixFunction(Function *func) {
#ifdef ARCH_X86_64
    SwitchContextPass switchContext(RET_RAX_CONTEXT_SIZE, RET_RAX_REGISTER_SAVE_LIST);
    func->accept(&switchContext);
#endif
}
