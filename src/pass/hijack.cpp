#include <cassert>
#include "hijack.h"
#include "chunk/link.h"
#include "conductor/conductor.h"
#include "instr/semantic.h"
#include "operation/find2.h"

#include "log/log.h"
#include "chunk/dump.h"

HijackPass::HijackPass(Conductor *conductor, const char *name) {
    original = ChunkFind2(conductor->getProgram()).findFunction(name, nullptr);
    assert(original);

    auto egalito = conductor->getProgram()->getEgalito();
    std::string name2 = std::string("egalito_") + std::string(name);
    wrapper = ChunkFind2().findFunctionInModule(name2.c_str(), egalito);
    assert(wrapper);
}

void HijackPass::visit(Module *module) {
    assert(module->getLibrary()->getRole() == Library::ROLE_MAIN);
    recurse(module);
}

void HijackPass::visit(Instruction *instruction) {
    auto semantic = instruction->getSemantic();
    auto link = semantic->getLink();
    if(!link) return;

    if(auto f = dynamic_cast<Function *>(link->getTarget())) {
        if(f == original) {
            semantic->setLink(new ExternalNormalLink(wrapper));
            delete link;
        }
    }
}

void HijackPass::visit(PLTTrampoline *trampoline) {
    auto external = trampoline->getExternalSymbol();
    auto f = dynamic_cast<Function *>(external->getResolved());
    if(f == original) {
        external->setResolved(wrapper);
    }
}
