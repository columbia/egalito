#include <iostream>
#include <sstream>
#include <cstdio>
#include "disassemble.h"
#include "elf/reloc.h"  // for dumping PLTLink
#include "dump.h"

void ChunkDumper::visit(Module *module) {
    recurse(module);
}

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
    cs_insn *ins = instruction->getSemantic()->getCapstone();

    int pos = INT_MIN;
    auto parent = instruction->getParent();
    if(parent) {
        auto currentPos = instruction->getPosition();
        auto parentPos = parent->getPosition();
        if(currentPos && parentPos) {
            pos = currentPos->get() - parentPos->get();
        }
    }

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
            else if(auto v = dynamic_cast<PLTLink *>(link)) {
                targetName << "PLT::" << v->getReloc()->getSymbolName();
            }
            else targetName << "[unresolved]";

            std::ostringstream name;
#ifdef ARCH_X86_64
            if(p->getMnemonic() == "callq") name << "(CALL)";
#elif defined(ARCH_AARCH64)
            if(p->getMnemonic() == "bl") name << "(CALL)";
#endif
            else name << "(JUMP " << p->getMnemonic() << ")";

            Disassemble::printInstructionRaw(instruction->getAddress(),
                pos,
                name.str().c_str(),
                link ? link->getTargetAddress() : 0,
                targetName.str().c_str());
        }
        else std::printf("...unknown...\n");
        return;
    }

    if(auto r = dynamic_cast<RelocationInstruction *>(instruction->getSemantic())) {
        auto link = r->getLink();
        auto target = link ? link->getTarget() : nullptr;
        if(target) {
            Disassemble::printInstruction(ins, pos, target->getName().c_str());
            return;
        }
    }

    // !!! we shouldn't need to modify the addr inside a dump function
    // !!! this is just to keep the cs_insn up-to-date
    ins->address = instruction->getAddress();
    Disassemble::printInstruction(ins, pos, target);
}
