#include "resolveplt.h"
#include "elf/symbol.h"
#include "chunk/program.h"
#include "load/emulator.h"
#include "operation/find2.h"

#include "log/log.h"
#include "log/temp.h"
#include "conductor/conductor.h"

void ResolvePLTPass::visit(Module *module) {
    LOG(1, "resolving PLT for " << module->getName());
    this->module = module;
    recurse(module);
}

void ResolvePLTPass::visit(PLTList *pltList) {
    recurse(pltList);
}

void ResolvePLTPass::visit(PLTTrampoline *pltTrampoline) {
    if(pltTrampoline->getTarget()) return;  // already resolved

    auto symbol = pltTrampoline->getExternalSymbol();
    auto link = PerfectLinkResolver().resolveExternally(symbol, conductor,
        module->getElfSpace(), false, true);
    if(!link) {
        link = PerfectLinkResolver().resolveExternally(symbol, conductor,
            module->getElfSpace(), true, true);
    }
    Chunk *target = nullptr;
    if(link) {
        target = link->getTarget();
        delete link;
    }

    if(!target) {
        // sometimes a PLT target is found in itself with version (e.g. __netf2)
        auto version = symbol->getVersion();
        std::string lookupName;
        lookupName.append(symbol->getName());
        if(version) {
            lookupName.push_back('@');
            if(!version->isHidden()) lookupName.push_back('@');
            lookupName.append(version->getName());
        }
        target = ChunkFind2().findFunctionInModule(lookupName.c_str(), module);
    }
    if(target) {
        LOG(10, "PLT to " << symbol->getName()
            << " resolved to " << target->getName()
            << " in " << target->getParent()->getParent()->getName());
        symbol->setResolved(target);

        if(target->getParent()) {
            symbol->setResolvedModule(dynamic_cast<Module *>(
                target->getParent()->getParent()));
        }
    }
    else {
        LOG(1, "unresolved pltTrampoline target "
            << symbol->getName() << " unused?");
#if 0
        if(symbol->getName() == "__netf2") {
            for(auto m : CIter::modules(conductor->getProgram())) {
                LOG(1, "checking in " << m->getName());
                for(auto f : CIter::functions(m)) {
                    if(m->getName() == "module-libgcc_s.so.1") {
                        LOG(1, "    " << f->getName());
                    }
                    if(f->hasName(symbol->getName())) {
                        LOG(1, "here! " << f->getName()
                            << " in " << m->getName());
                    }
                }
            }
            LOG(1, "not found?");
            std::cout.flush();
            exit(1);
        }
#endif
    }
}
