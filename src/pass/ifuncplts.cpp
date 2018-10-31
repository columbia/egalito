#include "ifuncplts.h"
#include "chunk/block.h"
#include "instr/concrete.h"
#include "disasm/disassemble.h"
#include "operation/mutator.h"
#include "log/log.h"

void IFuncPLTs::visit(Module *module) {
    recurse(module->getPLTList());
}

void IFuncPLTs::visit(PLTList *pltList) {
    recurse(pltList);
}

void IFuncPLTs::visit(PLTTrampoline *trampoline) {
    if(!trampoline->isIFunc()) return;

    freeChildren(trampoline, 2);

    auto block1 = new Block();
    PositionFactory *positionFactory = PositionFactory::getInstance();
    block1->setPosition(positionFactory->makePosition(nullptr, block1, 0));
    //block1->setPosition(new AbsolutePosition(0x0));
    {
        ChunkMutator m1(block1);
        m1.append(Disassemble::instruction({0x50}));  // push %rax
        m1.append(Disassemble::instruction({0x53}));  // push %rbx
        m1.append(Disassemble::instruction({0x51}));  // push %rcx
        m1.append(Disassemble::instruction({0x52}));  // push %rdx
        m1.append(Disassemble::instruction({0x56}));  // push %rsi
        m1.append(Disassemble::instruction({0x57}));  // push %rdi

        // note: keep stack 16-byte aligned for %xmm registers
        // the call instruction adds 8 bytes on its own, so push odd number first
        m1.append(Disassemble::instruction({0x52}));  // push %rdx

        auto call = new Instruction();
        auto callSem = new ControlFlowInstruction(X86_INS_CALL, call, "\xe8", "callq", 4);
        if(trampoline->getTarget()) {
            LOG(1, "creating IFUNC plt contents pointing to ["
                << trampoline->getTarget()->getName() << "]");
            callSem->setLink(new NormalLink(trampoline->getTarget(), Link::SCOPE_EXTERNAL_JUMP));
        }
        else {
            LOG(1, "creating IFUNC plt contents pointing to unresolved target! ["
                << trampoline->getExternalSymbol()->getName() << "]");
            callSem->setLink(new UnresolvedLink(0x0));
        }
        call->setSemantic(callSem);
        m1.append(call);
        // return value placed in %rax
    }

    {
        ChunkMutator m(trampoline, true);
        m.append(block1);
    }

    auto block2 = new Block();
    block2->setPosition(positionFactory->makePosition(block1, block2, block1->getSize()));
    //block2->setPosition(new AbsolutePosition(0x0));
    {
        ChunkMutator m2(block2);

        // mov %rax, %r11
        m2.append(Disassemble::instruction({0x49, 0x89, 0xc3}));

        m2.append(Disassemble::instruction({0x5a}));  // pop %rdx (alignment)
        m2.append(Disassemble::instruction({0x5f}));  // pop %rdi
        m2.append(Disassemble::instruction({0x5e}));  // pop %rsi
        m2.append(Disassemble::instruction({0x5a}));  // pop %rdx
        m2.append(Disassemble::instruction({0x59}));  // pop %rcx
        m2.append(Disassemble::instruction({0x5b}));  // pop %rbx
        m2.append(Disassemble::instruction({0x58}));  // pop %rax

        // jmp *%r11
        m2.append(Disassemble::instruction({0x41, 0xff, 0xe3}));
    }

    {
        ChunkMutator m(trampoline, true);
        m.append(block2);
    }
}

void IFuncPLTs::freeChildren(Chunk *chunk, int level) {
    if(level > 0) {
        for(int i = chunk->getChildren()->genericGetSize() - 1; i >= 0; i --) {
            auto child = chunk->getChildren()->genericGetAt(i);
            freeChildren(child, level-1);
            chunk->getChildren()->genericRemoveLast();
            delete child;
        }
    }
}
