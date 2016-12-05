#include <iostream>
#include <sstream>
#include <cstdio>
#include "disassemble.h"
#include "dump.h"

void ChunkDumper::visit(Function *function) {
    std::cout << "---[" << function->getName() << "]---\n";
    recurse(function);
}

void ChunkDumper::visit(Block *block) {
    //std::cout << ".block:\n";
    std::cout << block->getName() << ":\n";
    recurse(block);
}

void ChunkDumper::visit(Instruction *instruction) {
    const char *target = nullptr;
    auto pos = dynamic_cast<RelativePosition *>(instruction->getPosition());
    cs_insn *ins = instruction->getSemantic()->getCapstone();

    std::printf("    ");

    if(!ins) {
        if(auto p = dynamic_cast<ControlFlowInstruction *>(instruction->getSemantic())) {

            auto link = p->getLink();
            auto target = link ? link->getTarget() : nullptr;

            std::ostringstream targetName;
            if(target) {
                if(target->getName() != "???") {
                    targetName << target->getName().c_str();
                }
                else {
                    targetName << "target-" << std::hex << &target;
                }
            }
            else targetName << "[unresolved]";

            std::ostringstream name;
            if(p->getMnemonic() == "callq") name << "(CALL)";
            else name << "(JUMP " << p->getMnemonic() << ")";

            std::printf("0x%08lx <+%lu>:\t%s\t\t0x%lx <%s>\n",
                instruction->getAddress(),
                pos ? pos->getOffset() : 0,
                name.str().c_str(),
                link ? link->getTargetAddress() : 0,
                targetName.str().c_str());
        }
        else std::printf("...unknown...\n");
        return;
    }

    // !!! we shouldn't need to modify the addr inside a dump function
    // !!! this is just to keep the cs_insn up-to-date
    ins->address = instruction->getAddress();
    if(pos) {
        Disassemble::printInstructionAtOffset(ins, pos->getOffset(), target);
    }
    else {
        Disassemble::printInstruction(ins, target);
    }
}
