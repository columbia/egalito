#include <set>
#include "splitfunctions.h"
#include "chunk/concrete.h"
#include "chunk/dump.h"
#include "instr/concrete.h"
#include "operation/mutator.h"
#include "log/log.h"

void SplitFunctions::splitByDirectCall(Module *module) {
    PositionFactory *positionFactory = PositionFactory::getInstance();

    // Use a set to record split points, to maintain sortedness and
    // automatically discard duplicates.
    std::set<address_t> splitPoints;

    address_t maxFinalAddress = 0;

    LOG(1, "Finding function split points at direct calls");
    for(auto function : CIter::functions(module)) {
        splitPoints.insert(function->getAddress());

        for(auto block : CIter::children(function)) {
            for(auto instr : CIter::children(block)) {
                if(auto v = dynamic_cast<ControlFlowInstruction *>(instr->getSemantic())) {
#ifdef ARCH_X86_64
                    if(v->getMnemonic() == "callq")
#elif defined(ARCH_AARCH64)
                    if(v->getMnemonic() == "bl")
#elif defined(ARCH_ARM)
                    if(v->getMnemonic() == "bl" || semantic->getMnemonic() == "blx")
#endif
                    {
                        if(v->getLink()) {
                            LOG(2, "    function [" << function->getName()
                                << "] points to split at "
                                << std::hex << v->getLink()->getTargetAddress()
                                << " from:");
                            ChunkDumper dumper;
                            instr->accept(&dumper);
                            splitPoints.insert(v->getLink()->getTargetAddress());
                        }
                    }
                }
            }
        }

        address_t finalAddress = function->getAddress() + function->getSize();
        if(finalAddress > maxFinalAddress) maxFinalAddress = finalAddress;
    }

    // Add marker at the end of the last function.
    if(maxFinalAddress) {
        splitPoints.insert(maxFinalAddress);
    }

    LOG(1, "Splitting functions according to direct calls");

    FunctionList *newFunctionList = new FunctionList();

    std::set<address_t>::iterator it = splitPoints.begin();
    address_t address = (*it);
    Function *newFunction = new FuzzyFunction(address);
    newFunction->setPosition(
        positionFactory->makeAbsolutePosition(address));
    newFunctionList->getChildren()->add(newFunction);
    newFunction->setParent(newFunctionList);
    LOG(5, "    new function at 0x" << std::hex << address);
    for(auto function : CIter::functions(module)) {
        for(auto block : CIter::children(function)) {
            std::set<address_t>::iterator next = it;
            ++next;
            while(block->getAddress() >= (*next)) {
                ++it, ++next;
                address = (*it);
                newFunction = new FuzzyFunction(address);
                newFunction->setPosition(
                    positionFactory->makeAbsolutePosition(address));
                newFunctionList->getChildren()->add(newFunction);
                newFunction->setParent(newFunctionList);
                LOG(5, "    new function at 0x" << std::hex << address);
            }

            LOG(6, "        add block " << block->getName());

            ChunkMutator(newFunction, true).append(block);
        }
    }

    useFunctionList(module, newFunctionList);
}

void SplitFunctions::useFunctionList(Module *module, FunctionList *newList) {

    auto oldList = module->getFunctionList();
    if(oldList) {
        module->getChildren()->remove(oldList);
        module->setFunctionList(nullptr);

        // Here we free all functions and the old function list.
        // We are reusing the basic blocks and instruction classes.
        for(auto function : CIter::children(oldList)) {
            delete function;
        }
        delete oldList;
    }

    module->getChildren()->add(newList);
    module->setFunctionList(newList);
    newList->setParent(module);
}
