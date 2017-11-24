#include <cassert>
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
    recurse(dataRegionList);
}

void FixDataRegionsPass::visit(DataRegion *dataRegion) {
#ifdef ARCH_X86_64
    if(!dataRegion) return;
#endif
    for(auto dsec : CIter::children(dataRegion)) {
        for(auto var : CIter::children(dsec)) {
            if(isForIFuncJumpSlot(var)) continue;
            auto target = var->getDest()->getTargetAddress();
            // simply using var->getAddress() will fail due to TLS
            address_t address = var->getAddress()
                    + dataRegion->getMapBaseAddress()
                    - dsec->getAddress()
                    + dsec->getOriginalOffset();
            LOG(10, "set variable " << std::hex << address << " => " << target);
            *reinterpret_cast<address_t *>(address) = target;
        }
    }
}

bool FixDataRegionsPass::isForIFuncJumpSlot(DataVariable *var) {
    auto f = dynamic_cast<Function *>(&*var->getDest()->getTarget());
    if(!f) return false;

    if(auto sym = f->getSymbol()) {
        if(sym->getType() == Symbol::TYPE_IFUNC) return true;
    }

    return false;
}
