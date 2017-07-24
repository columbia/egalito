#include "fixdataregions.h"
#include "elf/elfspace.h"
#include "elf/symbol.h"
#include "log/log.h"

void FixDataRegionsPass::visit(Program *program) {
    this->program = program;
    recurse(program);
}

void FixDataRegionsPass::visit(Module *module) {
    LOG(1, "Fixing variables in regions for module " << module->getName());
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
    for(auto var : dataRegion->variableIterable()) {
        auto address = var->getAddress();
        if(auto tlsLink = dynamic_cast<TLSDataOffsetLink *>(var->getDest())) {
            if(!tlsLink->getTarget()) {
                auto sym = tlsLink->getSymbol();
                LOG(1, "trying to resolve (TLS Data) "
                    << sym->getName() << " at 0x" << std::hex
                    << sym->getAddress());

                for(auto m : CIter::children(program)) {
                    if(auto d = m->getElfSpace()->getSymbolList()
                        ->find(sym->getName())) {

                        LOG(1, "found the target in " << m->getName());
                        tlsLink->setTLSRegion(m->getDataRegionList()->getTLS());
                    }
                }
            }
        }

        auto target = var->getDest()->getTargetAddress();
        LOG(1, "set variable " << std::hex << address << " => " << target
            << " inside " << dataRegion->getName());
        *reinterpret_cast<address_t *>(address) = target;
    }
}
