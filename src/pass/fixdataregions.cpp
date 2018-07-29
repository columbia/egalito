#include <cassert>
#include "fixdataregions.h"
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
            if(!var->getDest()) {
                continue;
            }
            if(isForIFuncJumpSlot(var)) {
                continue;
            }
            auto target = var->getDest()->getTargetAddress();
            address_t address = var->getAddress();
            LOG(0, "set variable " << std::hex << address << " => " << target);
            if(var->getSize() == sizeof(address_t)) {
                *reinterpret_cast<address_t *>(address) = target;
            }
            else if(var->getSize() == 4) {
                *reinterpret_cast<uint32_t *>(address) = target;
            }
            else if(var->getSize() == 2) {
                *reinterpret_cast<uint16_t *>(address) = target;
            }
            else {
                assert(var->getSize() == 1);
                *reinterpret_cast<uint8_t *>(address) = target;
            }
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
