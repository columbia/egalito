#include <cassert>
#include <capstone/capstone.h>
#include "removepadding.h"
#include "chunk/concrete.h"
#include "instr/semantic.h"
#include "operation/mutator.h"

#include "log/log.h"
#include "log/temp.h"
#include "chunk/dump.h"

void RemovePadding::visit(Module *module) {
    //TemporaryLogLevel tll("pass", 10);
    recurse(module);

    ChunkMutator m(module->getFunctionList());
    for(auto f : emptyFunctions) {
        LOG(10, "removing (now) empty function: " << f->getName());
        assert(!f->getSymbol());
        m.remove(f);
    }
    std::cout.flush();
}

// the name of the function may not match the starting address after this
void RemovePadding::visit(Function *function) {
#ifdef ARCH_AARCH64
    if(function->getSize() == 0) {
        emptyFunctions.push_back(function);
        return;
    }

    if(!function->getSymbol()) {
        removeHead(function);
    }

    if(function->getSize() == 0) {
        emptyFunctions.push_back(function);
        return;
    }

    removeTail(function);
#endif

    if(function->getSize() == 0) {
        emptyFunctions.push_back(function);
    }
}

void RemovePadding::removeHead(Function *function) {
    auto firstBlock = function->getChildren()->getIterable()->get(0);
    auto firstInstr = dynamic_cast<Instruction *>(
        firstBlock->getChildren()->getIterable()->get(0));
    auto semantic = firstInstr->getSemantic();
    auto assembly = semantic->getAssembly();

    if(assembly && assembly->getId() == ARM64_INS_NOP) {
        LOG(10, "    first instruction is NOP");
        ChunkDumper dumper;
        function->accept(&dumper);

        // __GNUC__ >= 5 for AARCH64
        assert(firstInstr->getAddress() % 8);

        LOG(10, function->getName() << ":    removing first NOP");
        LOG(10, std::hex << firstInstr->getAddress());

        Chunk *next = nullptr;
        if(firstBlock->getChildren()->getIterable()->getCount() > 1) {
            next = firstBlock->getChildren()->getIterable()->get(1);
        }
        else if(function->getChildren()->getIterable()->getCount() > 1) {
            next = function->getChildren()->getIterable()->get(1);
        }

        if(next) {
            LOG(10, "        setting address to " << next->getAddress());
            ChunkMutator(function).setPosition(next->getAddress());
        }
        ChunkMutator(firstBlock).remove(firstInstr);
        delete firstInstr;
        delete semantic;
        if(firstBlock->getChildren()->getIterable()->getCount() == 0) {
            ChunkMutator(function).remove(firstBlock);
            delete firstBlock;
        }
    }
}

void RemovePadding::removeTail(Function *function) {
    auto lastBlock = function->getChildren()->getIterable()->getLast();
    auto lastInstr = dynamic_cast<Instruction *>(
        lastBlock->getChildren()->getIterable()->getLast());
    if(lastInstr) {
        auto semantic = lastInstr->getSemantic();
        auto assembly = semantic->getAssembly();
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
    }
}

