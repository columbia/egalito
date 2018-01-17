#include <cassert>
#include "ifunclazy.h"
#include "chunk/ifunc.h"

#include "log/log.h"
#include "log/temp.h"
#include "chunk/dump.h"
#include "pass/clearspatial.h"

void IFuncLazyPass::visit(Module *module) {
    //TemporaryLogLevel tll("pass", 10, module->getName() == "module-(egalito)");
    this->module = module;
    recurse(module->getPLTList());
}

void IFuncLazyPass::visit(PLTTrampoline *trampoline) {
    if(!trampoline->isIFunc()) return;

    ChunkDumper d;
    IF_LOG(10) trampoline->accept(&d);

    auto got = trampoline->getGotPLTEntry();
    ifuncList->addIFuncFor(got, trampoline->getTarget());

    auto region = module->getDataRegionList()->findRegionContaining(got);
    auto section = region->findDataSectionContaining(got);
    DataVariable *jumpslot = section->findVariable(got);
    assert(jumpslot);

    auto link = jumpslot->getDest();
    if(auto target = link->getTarget()) {
        LOG(10, "    target " << target->getName());
    }
    auto block = trampoline->getChildren()->getIterable()->get(1);
    auto instr = block->getChildren()->getIterable()->get(0);
    LOG(10, "    new target " << std::hex << instr->getAddress());

    jumpslot->setDest(new NormalLink(instr, Link::SCOPE_EXTERNAL_CODE));
    delete link;
}

