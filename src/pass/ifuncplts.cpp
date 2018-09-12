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
    freeChildren(trampoline, 2);

    auto block1 = new Block();
    {
        ChunkMutator m1(block1);
        m1.append(Disassemble::instruction({0x50}));  // push %rax
        m1.append(Disassemble::instruction({0x53}));  // push %rbx
        m1.append(Disassemble::instruction({0x51}));  // push %rcx

        auto call = new Instruction();
        auto callSem = new ControlFlowInstruction(X86_INS_CALL, call, "\xe8", "callq", 4);
        callSem->setLink(new NormalLink(trampoline->getTarget(), Link::SCOPE_EXTERNAL_JUMP));
        m1.append(call);
        // return value placed in %rax
    }

    auto block2 = new Block();
    {
        ChunkMutator m2(block2);

        // mov %rax, %r11
        m2.append(Disassemble::instruction({0x49, 0x89, 0xc3}));

        m2.append(Disassemble::instruction({0x59}));  // pop %rcx
        m2.append(Disassemble::instruction({0x5b}));  // pop %rbx
        m2.append(Disassemble::instruction({0x58}));  // pop %rax

        // jmp *%r11
        m2.append(Disassemble::instruction({0x41, 0xff, 0xe3}));
    }

    ChunkMutator(trampoline).append(block1);
    ChunkMutator(trampoline).append(block2);
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
