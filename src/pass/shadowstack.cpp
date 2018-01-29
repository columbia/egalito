#include <sys/mman.h>

#include "shadowstack.h"
#include "disasm/disassemble.h"
#include "operation/mutator.h"
#include "instr/concrete.h"
#include "log/log.h"

ShadowStack::ShadowStack(const char * stackStartAddress) : 
    offset(0x100000), size(0x200000), sentinel(0xffffffff) {
#ifdef ARCH_X86_64
    // allocate shadow stack at address
    size_t address = ( (size_t) stackStartAddress & ~0xfff ) + offset;
//    size_t address = ( (size_t) stackStartAddress & ~0xfff ) - offset;
    auto shadowStackStartAddress = mmap((void *) address,
        size, 
        PROT_WRITE | PROT_READ,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1, 0);

    if(shadowStackStartAddress == (void *)-1) throw "Out of memory?";
    LOG(1, "mapped to " << std::hex << shadowStackStartAddress);
    LOG(1, "expected " << std::hex << address);

    auto displacement = ((const char * ) shadowStackStartAddress - stackStartAddress) + size / 2;
//    auto displacement = (stackStartAddress - (const char * ) shadowStackStartAddress) + size / 2;
    auto offsetVector = intToBytes(displacement - sizeof(int *));
    LOG(1, "displacement in push instruction: " << std::hex << displacement - sizeof(int*) << "\n");
//   prologue:
//   8f 84 24 92 99 99 00    popq   0x999992(%rsp)
//   48 83 ec 08             sub    $0x8,%rsp
    std::vector<unsigned char> saveSSPInsnPrefix = {0x8f, 0x84, 0x24};
    saveSSPInsnPrefix.insert(saveSSPInsnPrefix.end(), offsetVector.begin(), offsetVector.end());
    saveSSPInsn = Disassemble::instruction(saveSSPInsnPrefix);

//   epilogue:
//   48 83 c4 08             add    $0x8,%rsp
//   ff b4 24 92 99 99 00    pushq  0x999992(%rsp)
//   48 c7 84 24 9A 99 99    movq   $0x1e240,(0x99999A)(%rsp)
//   00 ff ff ff ff
    std::vector<unsigned char> restoreSSPInsnPrefix = {0xff, 0xb4, 0x24};
    restoreSSPInsnPrefix.insert(restoreSSPInsnPrefix.end(), offsetVector.begin(), offsetVector.end());
    restoreSSPInsn = Disassemble::instruction(restoreSSPInsnPrefix);

#if 1
    std::vector<unsigned char> clearSSPInsnPrefix = {0x48, 0xc7, 0x84, 0x24};
    offsetVector = intToBytes(displacement);
    clearSSPInsnPrefix.insert(clearSSPInsnPrefix.end(), offsetVector.begin(), offsetVector.end());
    auto sentinelVector = intToBytes(sentinel);
    clearSSPInsnPrefix.insert(clearSSPInsnPrefix.end(), sentinelVector.begin(), sentinelVector.end());
    clearSSPInsn = Disassemble::instruction(clearSSPInsnPrefix);
#endif
#endif
}
 
void ShadowStack::visit(Function *function) {
    auto block1 = function->getChildren()->getIterable()->get(0);
    Instruction *first = nullptr;
    if (function->hasName("main")
            || function->hasName("my_write")) {
    if(block1->getChildren()->getIterable()->getCount() > 0) {
        first = block1->getChildren()->getIterable()->get(0);
    }
    addInstructions(block1, first, true);
    recurse(function);
    }
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
        // tail recursion
        if(v->getMnemonic() != "callq" && s->getLink()->isExternalJump()) {
            addInstructions(parent, instruction, false);
        }
    }
}

void ShadowStack::addInstructions(Block *block, Instruction *instruction, bool isPrologue) {
#ifdef ARCH_X86_64
    ChunkMutator mutator(block);
    if (isPrologue) {
//   48 83 ec 08             sub    $0x8,%rsp
        mutator.insertBefore(instruction, saveSSPInsn);
        mutator.insertBefore(instruction, Disassemble::instruction(
            {0x48, 0x83, 0xec, 0x08}));
    } else {
//   48 83 c4 08             add    $0x8,%rsp
        mutator.insertBefore(instruction, Disassemble::instruction(
            {0x48, 0x83, 0xc4, 0x08}));
        mutator.insertBefore(instruction, restoreSSPInsn);
        mutator.insertBefore(instruction, clearSSPInsn);
    }
#endif
}

std::vector<unsigned char> ShadowStack::intToBytes(int value) {
    std::vector<unsigned char> result;
    result.push_back(value >> 0);
    result.push_back(value >> 8);
    result.push_back(value >> 16);
    result.push_back(value >> 24);
    return result;
}
