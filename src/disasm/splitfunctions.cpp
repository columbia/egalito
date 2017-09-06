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
    }

    // Add marker at the end of the last function.
    auto last = CIter::iterable(module->getFunctionList())->getLast();
    splitPoints.insert(last->getAddress() + last->getSize());

    LOG(1, "Splitting functions according to direct calls");

    FunctionList *newFunctionList = new FunctionList();
    std::set<address_t>::iterator i = splitPoints.begin();
    std::set<address_t>::iterator next = i;
    next ++;
    while(next != splitPoints.end()) {
        address_t address = (*i);
        size_t size = (*next) - address;

        LOG(5, "    function at [0x" << std::hex << address << ",0x"
            << address + size << "]");

        // We assume here that we are only splitting functions into even
        // finer chunks and not combining them -- so we only need to look
        // in one function for our basic blocks.
        auto originalFunction = CIter::spatial(module->getFunctionList())
            ->findContaining(address);
        if(originalFunction) {
            LOG(8, "    looks like the source function is " << originalFunction->getName());
            auto relevantBlocks = CIter::spatial(originalFunction)
                ->findAllWithin(Range(address, size));

            auto newFunction = new FuzzyFunction(address);
            {
                ChunkMutator mutator(newFunction, true);
                for(auto block : relevantBlocks) {
                    mutator.append(block);
                }
            }
            newFunction->setPosition(
                positionFactory->makeAbsolutePosition(address));
            newFunctionList->getChildren()->add(newFunction);
            newFunction->setParent(newFunctionList);
        }

        ++i, ++next;
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
