#include "fixdataregions.h"
#include "elf/elfspace.h"
#include "elf/symbol.h"
#include "log/log.h"
#include "log/temp.h"

void FixDataRegionsPass::visit(Program *program) {
    this->program = program;
    recurse(program);
}

void FixDataRegionsPass::visit(Module *module) {
    //TemporaryLogLevel tll("pass", 10);
    LOG(1, "Fixing variables in regions for " << module->getName());
    this->module = module;
    visit(module->getDataRegionList());
}

void FixDataRegionsPass::visit(DataRegionList *dataRegionList) {
#ifdef ARCH_X86_64
    visit(dataRegionList->getTLS());
#elif defined(ARCH_AARCH64)
    recurse(dataRegionList);
#endif
}

void FixDataRegionsPass::visit(DataRegion *dataRegion) {
    if(!dataRegion) return;
    auto isTLS = dynamic_cast<TLSDataRegion *>(dataRegion);
    for(auto dsec : CIter::children(dataRegion)) {
        for(auto var : CIter::children(dsec)) {
            if(auto tlsLink
                = dynamic_cast<TLSDataOffsetLink *>(var->getDest())) {

                if(!tlsLink->getTarget()) {
                    resolveTLSLink(tlsLink);
                }
            }

            auto target = var->getDest()->getTargetAddress() + var->getAddend();
            address_t address = var->getAddress();
            if(!isTLS) {
                address += dataRegion->getMapBaseAddress()
                    - dsec->getAddress()
                    + dsec->getOriginalOffset();
            }
            LOG(1, "set variable " << std::hex << address << " => " << target);
            *reinterpret_cast<address_t *>(address) = target;
        }
    }
}

void FixDataRegionsPass::resolveTLSLink(TLSDataOffsetLink *link) {
    auto sym = link->getSymbol();
    LOG(10, "trying to resolve (TLS Data) "
        << sym->getName() << " at 0x" << std::hex
        << sym->getAddress());

    for(auto m : CIter::children(program)) {
        if(m == module) continue;

        if(auto targetSym = m->getElfSpace()->getSymbolList()
            ->find(sym->getName())) {

            if(targetSym->getSectionIndex() == SHN_UNDEF) continue;

            LOG(10, "found the target in " << m->getName() << " at "
                << targetSym->getAddress());

            link->setTLSRegion(m->getDataRegionList()->getTLS());
            link->setTarget(targetSym->getAddress());
            break;
        }
    }
}

