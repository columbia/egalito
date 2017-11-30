#include <cassert>
#include "fixifuncslot.h"

#include "log/log.h"
#include "log/temp.h"
#include "chunk/dump.h"

void FixIFuncSlotPass::visit(Module *module) {
    //TemporaryLogLevel tll("pass", 10, module->getName() == "module-(egalito)");
    this->module = module;
    recurse(module->getPLTList());
}

void FixIFuncSlotPass::visit(PLTTrampoline *trampoline) {
    if(!trampoline->isIFunc()) return;

    ChunkDumper d;
    IF_LOG(10) trampoline->accept(&d);

    DataVariable *jumpslot = nullptr;
    for(auto region : CIter::children(module->getDataRegionList())) {
        jumpslot = region->findVariable(trampoline->getGotPLTEntry());
        if(jumpslot) {
            LOG(10, "jumpslot found " << std::hex << jumpslot->getAddress());
            break;
        }
    }
    if(!jumpslot) {
        TemporaryLogLevel tll("chunk", 10);
        module->getDataRegionList()->accept(&d);
    }
    assert(jumpslot);

    auto link = jumpslot->getDest();
    if(auto target = link->getTarget()) {
        LOG(10, "    target " << target->getName());
    }
    auto block = trampoline->getChildren()->getIterable()->get(1);
    auto instr = block->getChildren()->getIterable()->get(0);
    LOG(10, "    new target " << std::hex << instr->getAddress());

    jumpslot->setDest(new NormalLink(instr));
    delete link;
}

