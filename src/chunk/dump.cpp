#include <cstdio>
#include "disassemble.h"
#include "dump.h"

void ChunkDumper::visit(Instruction *instruction) {
    const char *target = nullptr;
    auto pos = dynamic_cast<RelativePosition *>(instruction->getPosition());
    cs_insn *ins = instruction->getSemantic()->getCapstone();

    if(!ins) {
        if(auto p = dynamic_cast<ControlFlowInstruction *>(instruction->getSemantic())) {

            auto link = p->getLink();

            std::printf("0x%08lx <+%d>:\t%s\t\t0x%lx <%s>\n",
                instruction->getAddress(),
                pos ? pos->getOffset() : 0,
                "(CALL)", link ? link->getTargetAddress() : 0,
                "???");
        }
        else std::printf("...unknown...\n");
        return;
    }

    if(pos) {
        Disassemble::printInstructionAtOffset(ins, pos->getOffset(), target);
    }
    else {
        Disassemble::printInstruction(ins, target);
    }
}
