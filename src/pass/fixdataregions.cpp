#include "fixdataregions.h"
#include "log/log.h"

void FixDataRegionsPass::visit(Module *module) {
    LOG(1, "Fixing variables in regions for module " << module->getName());
    this->module = module;
    visit(module->getDataRegionList());
}

void FixDataRegionsPass::visit(DataRegionList *dataRegionList) {
    //recurse(dataRegionList);
    visit(dataRegionList->getTLS());
}

void FixDataRegionsPass::visit(DataRegion *dataRegion) {
    if(!dataRegion) return;
    for(auto var : dataRegion->variableIterable()) {
        auto address = var->getAddress();
        auto target = var->getDest()->getTargetAddress();
        LOG(1, "set variable " << std::hex << address << " => " << target
            << " inside " << dataRegion->getName());
        *reinterpret_cast<address_t *>(address) = target;
    }
}
