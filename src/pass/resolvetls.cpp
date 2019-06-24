#include "resolvetls.h"
#include "exefile/exefile.h"

#include "log/log.h"

void ResolveTLSPass::visit(Program *program) {
    this->program = program;
    recurse(program);
}

void ResolveTLSPass::visit(Module *module) {
    this->module = module;
    if(module->getDataRegionList()) {
        recurse(module->getDataRegionList());
    }
}

void ResolveTLSPass::visit(DataRegion *dataRegion) {
#ifdef ARCH_X86_64
    if(!dataRegion) return;
#endif
    for(auto dsec : CIter::children(dataRegion)) {
        for(auto var : CIter::children(dsec)) {
            if(auto tlsLink
                = dynamic_cast<TLSDataOffsetLink *>(var->getDest())) {

                if(!tlsLink->getTarget()) {
                    resolveTLSLink(tlsLink);
                }
            }
        }
    }
}

void ResolveTLSPass::resolveTLSLink(TLSDataOffsetLink *link) {
    auto sym = link->getSymbol();
    LOG(10, "trying to resolve (TLS Data) "
        << sym->getName() << " at 0x" << std::hex
        << sym->getAddress());

    for(auto m : CIter::children(program)) {
        if(m == module) continue;

        if(auto list = m->getExeFile()->getSymbolList()) {
            if(auto targetSym = list->find(sym->getName())) {

                if(targetSym->getSectionIndex() == SHN_UNDEF) continue;

                LOG(10, "found the target in " << m->getName() << " at "
                    << targetSym->getAddress());

                link->setTLSRegion(m->getDataRegionList()->getTLS());
                link->setTarget(targetSym->getAddress());
                break;
            }
        }
    }

    if(auto sym = link->getSymbol()) {
        if(sym->getBind() != Symbol::BIND_WEAK) {
            LOG(1, "[resolveTLSLink] unresolved non weak symbol");
        }
    }
}
