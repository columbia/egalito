#include "noppass.h"
#include "disasm/disassemble.h"
#include "instr/concrete.h"
#include "operation/mutator.h"
#include "log/log.h"

/*
void NopPass::visit(Instruction *instruction) {
#ifdef ARCH_X86_64
    LOG(1, "adding nop at " << instruction->getName());
//    auto nopIns = new Instruction();
    // either this or linked instruction?
    // link == reference to symbol or something else or function
//    auto nopSem = new ControlFlowInstruction(X86_INS_NOP, nopIns, "\x90", "nop", 4);
//    nopSem->setLink(new NormalLink(loggingEnd));
//    nopIns->setSemantic(nopSem);
    auto parent = dynamic_cast<Block *>(instruction_

    ChunkMutator(instruction->getParent())
        .insertBefore(instruction, Disassemble::instruction(
            {0x90}));
#endif
}
*/

void NopPass::visit(Block *block) {
#ifdef ARCH_X86_64
    LOG(1, "adding nops NEAR " << block->getName());
//    ChunkMutator mutator(block, false);
    ChunkMutator mutator(block);
    uint32_t instructionIndex = 0;
    auto instructionCount = block->getChildren()->getIterable()->getCount();
    if(instructionCount > 0) {
        while (instructionCount--) {
            auto instruction = block->getChildren()->getIterable()->get(instructionIndex);
//            if (instruction->getSemantic()->getAssembly()->getMnemonic() != ""){
 //               LOG(1, "adding nop at " << instruction->getSemantic()->getAssembly()->getMnemonic());
  //          } else {
                LOG(1, "adding nop at " << instruction->getSemantic()->getAssembly());
   //         }
//            DisasmDump::printInstruction(
            // true/false flag
            mutator.insertAfter(instruction, Disassemble::instruction({0x90}));
            // increment by 2 to avoid processing the nop instruction
            instructionIndex += 2;
        }
    }
#endif
}
