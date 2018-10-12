#include <iomanip>
#include "endbradd.h"
#include "disasm/disassemble.h"
#include "operation/mutator.h"
#include "operation/find2.h"
#include "instr/concrete.h"
#include "log/log.h"

void EndbrAddPass::visit(Program *program) {
    LOG(1, "Adding endbr instructions to all modules");

    recurse(program);

    auto egalito = program->getEgalito();
    if(egalito) {
        auto f = ChunkFind2(program).findFunctionInModule(
            "egalito_runtime_init", egalito);
        if(f) indirectTargets.insert(f);
    }

    {
        auto f = ChunkFind2(program).findFunctionInModule(
            "_start", program->getMain());
        auto f2 = dynamic_cast<Function *>(program->getEntryPoint());
        if(f) indirectTargets.insert(f);
        if(f2) indirectTargets.insert(f2); 
    }

    for(auto function : indirectTargets) {
        LOG(12, "    indirect target " << function->getName());
        auto block1 = function->getChildren()->getIterable()->get(0);
        auto instr1 = block1->getChildren()->getIterable()->get(0);
        auto semantic = instr1->getSemantic();
        if(auto v = dynamic_cast<IsolatedInstruction *>(semantic)) {
#ifdef ARCH_X86_64
            if(v->getAssembly()->getId() == X86_INS_ENDBR64) {
                // already an endbr
                continue;
            }
#endif
        }

        {
#ifdef ARCH_X86_64
            //    0:   f3 0f 1e fa             endbr64
            auto endbr = Disassemble::instruction({ 0xf3, 0x0f, 0x1e, 0xfa});
            ChunkMutator(block1, true).insertBefore(instr1, endbr);
            LOG(13, "    add endbr in [" << function->getName() << "]");
#endif
        }
    }
}

void EndbrAddPass::visit(Module *module) {
    recurse(module);  // to get to instructions
    recurse(module->getDataRegionList());  // to get to data variables
    recurse(module->getPLTList());  // to get IFUNC plt refs
    recurse(module->getInitFunctionList());
    recurse(module->getFiniFunctionList());

    static const char *entryPoints[] = {
        "_init",
        "frame_dummy"
    };

    for(auto name : entryPoints) {
        auto function = ChunkFind2(static_cast<Program *>(module->getParent()))
            .findFunctionInModule(name, module);
        if(function) {
            indirectTargets.insert(function);
        }
    }

    LOG(9, "after parsing module [" << module->getName()
        << "] we have " << std::dec << indirectTargets.size()
        << " indirect targets");
}

void EndbrAddPass::visit(DataVariable *variable) {
    if(variable->getDest() == nullptr) return;

    auto f = dynamic_cast<Function *>(variable->getDest()->getTarget());
    if(!f) return;
    //LOG(12, "    data var says that " << f->getName() << " is an indirect target");
    indirectTargets.insert(f);
}

void EndbrAddPass::visit(PLTTrampoline *pltTrampoline) {
    auto target = dynamic_cast<Function *>(pltTrampoline->getTarget());
    if(!target) return;

    // Assuming the collapseplt pass has been run, ordinary plt entries
    // do not constitute actual references to functions because they're 
    // never called. However, atleast in our current loader, IFUNC plt
    // entries (e.g. memcpy) are still used and we need to detect them here.
    if(!haveCollapsedPLT || pltTrampoline->isIFunc()) {
        indirectTargets.insert(target);
    }
}

void EndbrAddPass::visit(InitFunction *initFunction) {
    auto target = dynamic_cast<Function *>(initFunction->getLink()->getTarget());
    if(target) {
        indirectTargets.insert(target);
    }
}

void EndbrAddPass::visit(Instruction *instruction) {
    // should be a linked instruction
    auto li = dynamic_cast<LinkedInstruction *>(instruction->getSemantic());
    if(!li) return;

    auto link = li->getLink();
    auto target = link->getTarget();
    auto func_target = dynamic_cast<Function *>(target);
    if(func_target) {
        indirectTargets.insert(func_target);
    }
    else if(auto plt = dynamic_cast<PLTTrampoline *>(target)) {
        if(auto ext_target
            = dynamic_cast<Function *>(plt->getTarget())) {
            indirectTargets.insert(ext_target);
        }
        else {
            LOG(1, "warning: plt isn't resolved to a function");
            LOG(1, instruction->getParent()->getParent()->getName() 
                << ": " << plt->getName());
        }
    }
}

