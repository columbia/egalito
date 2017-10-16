#include <cassert>
#include <capstone/capstone.h>
#include "removepadding.h"
#include "chunk/concrete.h"
#include "instr/semantic.h"
#include "operation/mutator.h"

#include "log/log.h"
#include "log/temp.h"

void RemovePadding::visit(Module *module) {
    //TemporaryLogLevel tll("pass", 10);
    recurse(module);
}

// the name of the function may not match the starting address after this
void RemovePadding::visit(Function *function) {
#ifdef ARCH_AARCH64
    auto firstBlock = function->getChildren()->getIterable()->get(0);
    auto firstInstr = static_cast<Instruction *>(
        firstBlock->getChildren()->getIterable()->get(0));
    auto semantic = firstInstr->getSemantic();
    auto assembly = semantic->getAssembly();
    if(!function->getSymbol()
        && assembly && assembly->getId() == ARM64_INS_NOP) {

        LOG(10, function->getName() << ":    removing first NOP");
        LOG(10, std::hex << firstInstr->getAddress());
        // __GNUC__ >= 5 for AARCH64
        assert(firstInstr->getAddress() % 8);

        auto nextInstr = static_cast<Instruction *>(
            firstBlock->getChildren()->getIterable()->get(1));

        LOG(10, "        setting address to " << nextInstr->getAddress());
        ChunkMutator(function).setPosition(nextInstr->getAddress());
        ChunkMutator(firstBlock).remove(firstInstr);
        delete semantic;
        delete firstInstr;
        if(firstBlock->getChildren()->getIterable()->getCount() == 0) {
            ChunkMutator(function).remove(firstBlock);
            delete firstBlock;
        }
    }

    // this needs to run for functions whose size is estimated
    auto lastBlock = function->getChildren()->getIterable()->getLast();
    auto lastInstr = static_cast<Instruction *>(
        lastBlock->getChildren()->getIterable()->getLast());
    semantic = lastInstr->getSemantic();
    assembly = semantic->getAssembly();
    if(assembly && assembly->getId() == ARM64_INS_NOP) {
        LOG(10, function->getName() << ":    removing last NOP at "
            << std::hex << lastInstr->getAddress());
        ChunkMutator(lastBlock).removeLast();
        delete semantic;
        delete lastInstr;
        if(lastBlock->getChildren()->getIterable()->getCount() == 0) {
            ChunkMutator(function).removeLast();
            delete lastBlock;
        }
    }
#endif
}
