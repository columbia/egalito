#include <capstone/capstone.h>
#include <capstone/arm64.h>
#include "chunk/instruction.h"
#include "controlflow.h"
#include "log/log.h"

void ControlFlowPass::visit(Module *module) {
    recurse(module);
}

void ControlFlowPass::visit(Instruction *instruction) {
    cs_insn *cs = instruction->getSemantic()->getCapstone();
#if defined(ARCH_X86_64)
#elif defined(ARCH_AARCH64)
    if((cs->id == ARM64_INS_B)
       || (cs->id == ARM64_INS_BL)) {
        auto oldSemantic = instruction->getSemantic();
        auto i = new ControlFlowInstruction(instruction, *cs);
        i->setLink(new UnresolvedLink(i->getOriginalOffset()));
        instruction->setSemantic(i);
        delete oldSemantic;
    }
#endif
}
