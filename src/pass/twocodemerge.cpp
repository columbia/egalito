#include <cstring>  // for memset
#include <typeinfo> // for typeid
#include "twocodemerge.h"
#include "chunk/link.h"
#include "instr/semantic.h"
#include "operation/find2.h"
#include "log/log.h"

void TwocodeMergePass::visit(Module *module) {
    auto program = static_cast<Program *>(module->getParent());

    LOG(0, "merging [" << otherModule->getName() << "] into ["
        << module->getName() << "]");

    for(auto otherFunc : CIter::functions(otherModule)) {
        auto func = ChunkFind2(program)
            .findFunctionInModule(otherFunc->getName().c_str(), module);
        if(!func) continue;

        LOG(0, "merging [" << otherFunc->getName() << "]");

        bool allResolved = true;
        for(auto otherBlock : CIter::children(otherFunc)) {
            for(auto otherInstr : CIter::children(otherBlock)) {
                auto link = otherInstr->getSemantic()->getLink();
                if(!link) continue;
                if(!link->isExternalJump()) continue;

                LOG(0, "    link to " << link->getTargetAddress() << ", type "
                    << typeid(*link).name());
                if(auto v = dynamic_cast<AbsoluteNormalLink *>(link)) {
                    assert(false && "Did not expect AbsoluteNormalLink in twocode");
                }
                else if(auto v = dynamic_cast<NormalLink *>(link)) {
                    if(auto oldRef = dynamic_cast<Function *>(link->getTarget())) {
                        auto newRef = ChunkFind2(program).findFunctionInModule(
                            oldRef->getName().c_str(), module);
                        otherInstr->getSemantic()->setLink(
                            new NormalLink(newRef, link->getScope()));
                    }
                    else {
                        LOG(0, "    NormalLink does not target function, but rather "
                            << typeid(*link->getTarget()).name());
                        allResolved = false;
                    }
                }
                else if(auto v = dynamic_cast<PLTLink *>(link)) {
                    auto oldRef = v->getPLTTrampoline();
                    auto newRef = CIter::named(module->getPLTList())->find(
                        oldRef->getName());
                    if(newRef) {
                        otherInstr->getSemantic()->setLink(
                            new PLTLink(newRef->getAddress(), newRef));  // address 0???
                    }
                    else {
                        LOG(0, "    PLTLink targets unknown function ["
                            << oldRef->getName() << "]");
                        allResolved = false;
                    }
                }
                else if(auto v = dynamic_cast<AbsoluteDataLink *>(link)) {
                    assert(false && "Did not expect AbsoluteDataLink in twocode");
                }
                else if(auto v = dynamic_cast<DataOffsetLink *>(link)) {
                    auto section = static_cast<DataSection *>(v->getTarget());
                    auto addend = v->getAddend();
                    auto offset = v->getTargetAddress() - section->getAddress() - addend;

                    if(section->getType() == DataSection::TYPE_DATA
                        || section->getType() == DataSection::TYPE_BSS) {

                        //if(section->getName() == ".rodata") {
                        if(!static_cast<DataRegion *>(section->getParent())->writable()) {
                            // nothing, allow using rhs section for e.g. .rodata
                        }
                        else {
                            // assume data sections have the same layout
                            auto newRef = module->getDataRegionList()->findDataSection(
                                section->getName());
                            if(newRef) {
                                auto newLink = new DataOffsetLink(
                                    newRef, newRef->getAddress(), v->getScope());
                                newLink->setAddend(addend);
                                otherInstr->getSemantic()->setLink(newLink);
                            }
                            else {
                                LOG(0, "    DataOffsetLink targets section ["
                                    << section->getName()
                                    << "] which does not occur in lhs");
                                allResolved = false;
                            }
                        }
                    }
                    else {
                        LOG(0, "    DataOffsetLink targets section ["
                            << section->getName() << "] of unsupported type");
                        allResolved = false;
                    }
                }
                else {
                    allResolved = false;
                }
            }
        }
        if(allResolved) {
            transformed.push_back(otherFunc);
        }
        else LOG(0, "    SOME UNHANDLED LINK TYPES ABOVE");
    }
}
void TwocodeMergePass::copyFunctionsTo(Module *module) {
    for(auto otherFunc : transformed) {
        otherFunc->setName(otherFunc->getName() + "$rhs");

        char *name = new char[otherFunc->getName().length() + 1];
        std::strcpy(name, otherFunc->getName().c_str());
        otherFunc->getSymbol()->setName(name);

        otherModule->getFunctionList()->getChildren()->getIterable()->remove(otherFunc);
        module->getFunctionList()->getChildren()->getIterable()->add(otherFunc);
        otherFunc->setParent(module->getFunctionList());
    }
}
