#include <capstone/capstone.h>
#include <capstone/arm64.h>
#include "chunk/instruction.h"
#include "findreturn.h"
#include "log/log.h"

void FindReturnPass::visit(Module *module) {
    recurse(module);
}

void FindReturnPass::visit(Instruction *instruction) {
#if defined(ARCH_X86_64)
#elif defined(ARCH_AARCH64)
    cs_insn *cs = instruction->getSemantic()->getCapstone();
    if(cs && cs->id == ARM64_INS_RET) { //RET (<Xn>)
        auto oldSemantic = instruction->getSemantic();

        auto i = new ReturnInstruction(*cs);

        instruction->setSemantic(i);
        delete oldSemantic;
    }
#endif
}
