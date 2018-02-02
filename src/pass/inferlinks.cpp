#include "inferlinks.h"
#include "chunk/dump.h"
#include "disasm/makesemantic.h"
#include "log/log.h"

void InferLinksPass::visit(Module *module) {
    this->module = module;
#ifdef ARCH_AARCH64
    LinkedInstruction::makeAllLinked(module);
#else
    recurse(module);
#endif
}

void InferLinksPass::visit(Instruction *instruction) {
    auto semantic = instruction->getSemantic();
    if(dynamic_cast<IndirectCallInstruction *>(semantic)) {
        // if this is RIP-relative, we should try to convert this to
        // ControlFlowInstruction
        return;
    }
    if(dynamic_cast<IndirectJumpInstruction *>(semantic)) {
        return;
    }
    if(semantic->getLink()) return;
    auto assembly = semantic->getAssembly();
    if(!assembly) return;

#ifdef ARCH_X86_64
    // see if this instruction has any operands that need links
    // (can return NULL if not)
    auto linked = LinkedInstruction::makeLinked(module, instruction, assembly);
    if(linked) {
        instruction->setSemantic(linked);
        delete semantic;
    }
#elif defined(ARCH_ARM)
    auto linked = LinkedInstruction::makeLinked(module, instruction, assembly);
    if(linked) {
        instruction->setSemantic(linked);
        delete semantic;
    }
#endif
}
