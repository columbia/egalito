#include <iostream>
#include <sstream>
#include <cstdio>
#include "disasm/dump.h"
#include "disasm/disassemble.h"
#include "chunk/plt.h"  // for dumping PLTLink
#include "dump.h"
#include "log/log.h"

void ChunkDumper::visit(Module *module) {
    recurse(module);
}
void ChunkDumper::visit(FunctionList *functionList) {
    recurse(functionList);
}
void ChunkDumper::visit(BlockSoup *blockSoup) {
    recurse(blockSoup);
}
void ChunkDumper::visit(PLTList *pltList) {
    recurse(pltList);
}

void ChunkDumper::visit(Function *function) {
    LOG(4, "---[" << function->getName() << "]---");
    recurse(function);
}

void ChunkDumper::visit(Block *block) {
    LOG(4, block->getName() << ":");
    recurse(block);
}

void ChunkDumper::visit(Instruction *instruction) {
    const char *target = nullptr;
    Assembly *assembly = instruction->getSemantic()->getAssembly();

    int pos = INT_MIN;
    auto parent = instruction->getParent();
    if(parent) {
        auto currentPos = instruction->getPosition();
        auto parentPos = parent->getPosition();
        if(currentPos && parentPos) {
            pos = currentPos->get() - parentPos->get();
        }
    }

    CLOG0(4, "    ");

    if(!assembly) {
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
                targetName << v->getPLTTrampoline()->getName();
            }
            else targetName << "[unresolved]";

            std::ostringstream name;
#ifdef ARCH_X86_64
            if(p->getMnemonic() == "callq") name << "(CALL)";
#elif defined(ARCH_AARCH64)
            if(p->getMnemonic() == "bl") name << "(CALL)";
#endif
            else {
                name << "(JUMP " << p->getMnemonic() << ")";
                //name << " [opcode size " << p->getOpcode().length() << ", dispSize " << p->getDisplacementSize() << "] ";
            }

            std::string bytes = instruction->getSemantic()->getData();
            std::string bytes2 = DisasmDump::formatBytes(bytes.c_str(), bytes.size());

            DisasmDump::printInstructionRaw(instruction->getAddress(),
                pos,
                name.str().c_str(),
                link ? link->getTargetAddress() : 0,
                targetName.str().c_str(),
                bytes2.c_str());
        }
#ifdef ARCH_AARCH64
        else if(auto p = dynamic_cast<PCRelativeInstruction *>(
            instruction->getSemantic())) {

            auto link = p->getLink();
            auto target = link ? link->getTarget() : nullptr;
            auto name = target ? target->getName().c_str() : nullptr;
            DisasmDump::printInstruction(
                instruction->getAddress(), p->getAssembly(), pos, name);
        }
        else if(auto p = dynamic_cast<RawInstruction *>(
            instruction->getSemantic())) {

            std::vector<unsigned char> v(p->getData().begin(),
                                         p->getData().end());
            cs_insn instr = Disassemble::getInsn(v, instruction->getAddress());
            Assembly assembly(instr);
            DisasmDump::printInstruction(
                instruction->getAddress(), &assembly, pos, nullptr);
        }
#endif
        else LOG(4, "...unknown...");
        return;
    }

    // this handles RelocationInstruction, InferredInstruction
    if(auto r = dynamic_cast<LinkedInstruction *>(instruction->getSemantic())) {
        r->regenerateAssembly();
        auto link = r->getLink();
        auto target = link ? link->getTarget() : nullptr;
        if(target) {
            DisasmDump::printInstruction(
                instruction->getAddress(), assembly, pos, target->getName().c_str());
        }
        else {
            unsigned long targetAddress = link->getTargetAddress();
            DisasmDump::printInstructionCalculated(
                instruction->getAddress(), assembly, pos, targetAddress);
        }
        return;
    }

    if(auto p = dynamic_cast<IndirectJumpInstruction *>(instruction->getSemantic())) {
        std::ostringstream name;
        name << "(JUMP* " << p->getMnemonic() << ")";

        std::string bytes = instruction->getSemantic()->getData();
        std::string bytes2 = DisasmDump::formatBytes(bytes.c_str(), bytes.size());

        DisasmDump::printInstructionRaw(instruction->getAddress(),
            pos, name.str().c_str(),
            p->getAssembly()->getOpStr(), nullptr, bytes2.c_str(), false);
        return;
    }

    DisasmDump::printInstruction(instruction->getAddress(), assembly, pos, target);
}

void ChunkDumper::visit(PLTTrampoline *trampoline) {
    LOG(1, "NYI");
}
