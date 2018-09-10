#include "ldsorefs.h"
#include "chunk/concrete.h"
#include "instr/concrete.h"
#include "disasm/disassemble.h"
#include "operation/mutator.h"
#include "log/log.h"

void LdsoRefsPass::visit(Program *program) {
    program->getLibc()->accept(this);
}

void LdsoRefsPass::visit(Module *module) {
    auto xorInstr = Disassemble::instruction({0x48, 0x31, 0xc0});
    auto retInstr = Disassemble::instruction({0xc3});
    auto block = new Block();

    auto symbol = new Symbol(0x0, 0, "egalito_ldso_empty",
       Symbol::TYPE_FUNC, Symbol::BIND_GLOBAL, 0, 0);
    auto function = new Function(symbol);
    function->setName(symbol->getName());
    function->setPosition(new AbsolutePosition(0x0));

    module->getFunctionList()->getChildren()->add(function);
    function->setParent(module->getFunctionList());
    ChunkMutator(function).append(block);
    ChunkMutator m(block);
    m.append(xorInstr);
    m.append(retInstr);

    this->emptyTarget = function;
    recurse(module);
}

void LdsoRefsPass::visit(Function *function) {
    if(function->getName() == "_dl_addr"
        || function->getName() == "ptmalloc_init.part.0") {

        recurse(function);
    }
}

void LdsoRefsPass::visit(Instruction *instruction) {
    if(auto v = dynamic_cast<ControlFlowInstruction *>(instruction->getSemantic())) {
        auto link = v->getLink();
        if(!link || !link->getTarget()) return;
        LOG(0, "consider replacing call target " << link->getTarget()->getName());

        const char *names[] = {
            "_dl_find_dso_for_object@plt",
            "__tunable_get_val@plt",
        };

        for(const char *name : names) {
            if(link->getTarget()->getName() == name) {
                LOG(0, "replace call target from " << link->getTarget()->getName()
                    << " to " << emptyTarget->getName()); 
                v->setLink(new NormalLink(emptyTarget, Link::SCOPE_WITHIN_MODULE));
                delete link;
                break;
            }
        }
    }
}
