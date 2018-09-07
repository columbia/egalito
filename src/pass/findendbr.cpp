#include "findendbr.h"
#include "instr/concrete.h"
#include "log/log.h"

void FindEndbrPass::visit(Module *module) {
    LOG(9, "Searching for endbr in [" << module->getName() << "]");
    recurse(module);
}

void FindEndbrPass::visit(Function *function) {
    currentFunction = function;
    recurse(function);
    if (brCount[function]) {
        LOG(9, "Number of endbr instructions in [" << function->getName()
            << "] is " << brCount[function]);
    }
}

void FindEndbrPass::visit(Instruction *instruction) {
    auto semantic = instruction->getSemantic();
    if (auto v = dynamic_cast<IsolatedInstruction *>(semantic)) {
#ifdef ARCH_X86_64
        if (v->getAssembly()->getId() == X86_INS_ENDBR64) {
            brCount[currentFunction]++;
        }
#endif
    }
}
