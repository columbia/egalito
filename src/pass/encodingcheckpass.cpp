#include "encodingcheckpass.h"
#include "instr/linked-aarch64.h"
#include "log/log.h"

void EncodingCheckPass::visit(Module *module) {
    LOG(1, "CheckPass " << module->getName());
    recurse(module);
}

void EncodingCheckPass::visit(Instruction *instruction) {
    if(auto linked = dynamic_cast<LinkedInstruction *>(
        instruction->getSemantic())) {

        LOG(10, "checking " << std::hex << instruction->getAddress());
        linked->check();
    }
}
