#include "noppass.h"
#include "disasm/disassemble.h"
#include "instr/concrete.h"
#include "operation/mutator.h"
#include "log/log.h"

void NopPass::visit(Block *block) {
#ifdef ARCH_X86_64
    ChunkMutator mutator(block);
    uint32_t instructionIndex = 0;
    auto instructionCount = block->getChildren()->getIterable()->getCount();

    if(instructionCount > 0) {
        while (instructionCount--) {
            auto instruction = block->getChildren()->getIterable()->get(instructionIndex);
            mutator.insertAfter(instruction, Disassemble::instruction({0x90}));
            // increment by 2 to avoid processing the nop instruction
            instructionIndex += 2;
        }
    }
#endif
}
