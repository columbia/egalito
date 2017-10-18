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
    LOG(10, "Fixing variables in regions for " << module->getName());
    this->module = module;
    visit(module->getDataRegionList());
}

void FixDataRegionsPass::visit(DataRegionList *dataRegionList) {
#ifdef ARCH_X86_64
    //visit(dataRegionList->getTLS());
    recurse(dataRegionList);
#elif defined(ARCH_AARCH64)
    recurse(dataRegionList);
#endif
}

void FixDataRegionsPass::visit(DataRegion *dataRegion) {
#ifdef ARCH_X86_64
    if(!dataRegion) return;
#endif
    for(auto dsec : CIter::children(dataRegion)) {
        for(auto var : CIter::children(dsec)) {
            auto target = var->getDest()->getTargetAddress();
            address_t address = var->getAddress()
                    + dataRegion->getMapBaseAddress()
                    - dsec->getAddress()
                    + dsec->getOriginalOffset();
            LOG(10, "set variable " << std::hex << address << " => " << target);
            *reinterpret_cast<address_t *>(address) = target;
        }
    }
}

