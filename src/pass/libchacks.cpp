#include "libchacks.h"
#include "operation/find2.h"
#include "operation/mutator.h"
#include "disasm/disassemble.h"
#include "instr/concrete.h"
#include "log/log.h"

void LibcHacksPass::visit(Module *module) {
#ifdef ARCH_X86_64
    const char *funcs[] = {
        "memmove", "__memmove_chk",
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
    ChunkMutator m(func->getChildren()->getIterable()->get(0));
    m.prepend(Disassemble::instruction({0x52}));  // push %rdx

    for(auto block : CIter::children(func)) {
        for(auto ins : CIter::children(block)) {
            auto s = ins->getSemantic();
            if(dynamic_cast<ReturnInstruction *>(s)) {
                ChunkMutator(block).insertBeforeJumpTo(ins,
                    Disassemble::instruction({0x5a})); // pop %rdx
            }
            if(auto v = dynamic_cast<ControlFlowInstruction *>(s)) {
                if(v->getMnemonic() != "callq"
                    && dynamic_cast<ExternalNormalLink *>(s->getLink())) {

                    ChunkMutator(block).insertBeforeJumpTo(ins,
                        Disassemble::instruction({0x5a})); // pop %rdx
                }
            }
        }
    }
#endif
}
