#include "shadowstack.h"
#include "disasm/disassemble.h"
#include "operation/mutator.h"
#include "instr/concrete.h"

ShadowStack::ShadowStack() : size(0x1000000) {
#ifdef ARCH_X86_64
    auto offsetVector = intToBytes(size - sizeof(int *));

//   prologue:
//   67 8f 84 24 96 99 99 00   popq   0x999996(%esp)
//   83 ec 08                  sub    $0x8,%esp
    std::vector<unsigned char> prologuePrefix = {0x67, 0x8f, 0x84, 0x24};
    prologuePrefix.insert(prologuePrefix.end(), offsetVector.begin(), offsetVector.end());
    prologue = Disassemble::instruction(prologuePrefix);

//   epilogue:
//   83 c4 08                  add    $0x8,%esp
//   67 ff b4 24 96 99 99 00   pushq  0x999996(%esp)
    std::vector<unsigned char> epiloguePrefix = {0x67, 0xff, 0xb4, 0x24};
    epiloguePrefix.insert(epiloguePrefix.end(), offsetVector.begin(), offsetVector.end());
    epilogue = Disassemble::instruction(epiloguePrefix);
#endif
}
 
void ShadowStack::visit(Function *function) {
    auto block1 = function->getChildren()->getIterable()->get(0);
    Instruction *first = nullptr;
    if(block1->getChildren()->getIterable()->getCount() > 0) {
        first = block1->getChildren()->getIterable()->get(0);
    }
    addInstructions(block1, first, true);
    recurse(function);
}

void ShadowStack::visit(Block *block) {
    recurse(block);
}

void ShadowStack::visit(Instruction *instruction) {
    auto parent = dynamic_cast<Block *>(instruction->getParent());
    auto s = instruction->getSemantic();
    if(dynamic_cast<ReturnInstruction *>(s)) {
        addInstructions(parent, instruction, false);
    }
    else if(auto v = dynamic_cast<ControlFlowInstruction *>(s)) {
        // taken from StackXOR.cpp not a call, but still external; must be tail recursion
        if(v->getMnemonic() != "callq" && s->getLink()->isExternalJump()) {
            addInstructions(parent, instruction, false);
        }
    }
}

void ShadowStack::addInstructions(Block *block, Instruction *instruction, bool isPrologue) {
#ifdef ARCH_X86_64
    ChunkMutator mutator(block);
    if (isPrologue) {
        mutator.insertBefore(instruction, prologue);
        mutator.insertBefore(instruction, Disassemble::instruction(
            {0x83, 0xec, 0x08}));
    } else {
        mutator.insertBefore(instruction, Disassemble::instruction(
            {0x83, 0xc4, 0x08}));
        mutator.insertBefore(instruction, epilogue);
    }
#endif
}

std::vector<unsigned char> ShadowStack::intToBytes(int value) {
    std::vector<unsigned char> result;
    result.push_back(value >> 24);
    result.push_back(value >> 16);
    result.push_back(value >> 8);
    result.push_back(value >> 0);
    return result;
}
