#include <iostream>
#include <sstream>
#include <cstdio>
#include "dump.h"
#include "disasm/dump.h"
#include "disasm/disassemble.h"
#include "elf/symbol.h"
#include "log/log.h"

void ChunkDumper::visit(Module *module) {
    auto count = module->getChildren()->getIterable()->getCount();
    LOG(4, "=== [" << module->getName() << "] with " << count << " functions ===");
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
void ChunkDumper::visit(JumpTableList *jumpTableList) {
    recurse(jumpTableList);
}
void ChunkDumper::visit(DataRegionList *dataRegionList) {
    recurse(dataRegionList);
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
    auto semantic = instruction->getSemantic();
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

    if(auto p = dynamic_cast<ControlFlowInstruction *>(semantic)) {

        dumpInstruction(p, instruction->getAddress(), pos);
    }
    // this handles RelocationInstruction, InferredInstruction
    else if(auto r = dynamic_cast<LinkedInstruction *>(semantic)) {

        dumpInstruction(r, instruction->getAddress(), pos);
    }
    else if(auto p = dynamic_cast<IndirectJumpInstruction *>(semantic)) {

        dumpInstruction(p, instruction->getAddress(), pos);
    }
    else {
        dumpInstruction(semantic, instruction->getAddress(), pos);
    }
}

void ChunkDumper::visit(PLTTrampoline *trampoline) {
    LOG(4, "---[" << trampoline->getName() << "]---");
    LOG(1, "should be located at: 0x" << std::hex << trampoline->getAddress());
}

void ChunkDumper::visit(JumpTable *jumpTable) {
    LOG(1, "jump table in ["
        << jumpTable->getFunction()->getName() << "] at 0x"
        << std::hex << jumpTable->getAddress() << " with "
        << std::dec << jumpTable->getEntryCount()
        << " entries");
}

void ChunkDumper::visit(JumpTableEntry *jumpTableEntry) {
    LOG(1, "NYI");
}

void ChunkDumper::visit(DataRegion *dataRegion) {
    LOG(1, "NYI");
}

void ChunkDumper::dumpInstruction(ControlFlowInstruction *semantic,
    address_t address, int pos) {

    auto link = semantic->getLink();
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
    else if(auto v = dynamic_cast<SymbolOnlyLink *>(link)) {
        targetName << v->getSymbol()->getName() << "@symonly";
    }
    else targetName << "[unresolved]";

    std::ostringstream name;
#ifdef ARCH_X86_64
    if(semantic->getMnemonic() == "callq") name << "(CALL)";
#elif defined(ARCH_AARCH64)
    if(semantic->getMnemonic() == "bl") name << "(CALL)";
#elif defined(ARCH_ARM)
    if(semantic->getMnemonic() == "bl" || semantic->getMnemonic() == "blx") name << "(CALL)";
#endif
    else {
        name << "(JUMP " << semantic->getMnemonic() << ")";
        //name << " [opcode size " << semantic->getOpcode().length() << ", dispSize " << semantic->getDisplacementSize() << "] ";
    }

    std::string bytes = semantic->getData();
    std::string bytes2 = DisasmDump::formatBytes(bytes.c_str(), bytes.size());

    DisasmDump::printInstructionRaw(address,
        pos,
        name.str().c_str(),
        link ? link->getTargetAddress() : 0,
        targetName.str().c_str(),
        bytes2.c_str());
}

void ChunkDumper::dumpInstruction(LinkedInstruction *semantic,
    address_t address, int pos) {

    semantic->regenerateAssembly();
    Assembly *assembly = semantic->getAssembly();
    auto link = semantic->getLink();
    auto target = link ? link->getTarget() : nullptr;
    if(target) {
        DisasmDump::printInstruction(
            address, assembly, pos, target->getName().c_str());
    }
    else {
        unsigned long targetAddress = link->getTargetAddress();
        DisasmDump::printInstructionCalculated(
            address, assembly, pos, targetAddress);
    }
}

void ChunkDumper::dumpInstruction(IndirectJumpInstruction *semantic,
    address_t address, int pos) {

    std::ostringstream name;
    name << "(JUMP* " << semantic->getMnemonic() << ")";

    std::string bytes = semantic->getData();
    std::string bytes2 = DisasmDump::formatBytes(bytes.c_str(), bytes.size());

    DisasmDump::printInstructionRaw(address,
        pos, name.str().c_str(),
        semantic->getAssembly()->getOpStr(), nullptr, bytes2.c_str(), false);
}

void ChunkDumper::dumpInstruction(InstructionSemantic *semantic,
    address_t address, int pos) {

    Assembly *assembly = semantic->getAssembly();

    if(assembly) {
        DisasmDump::printInstruction(address, assembly, pos, nullptr);
    }
    else {  /* RawInstruction */
        std::vector<unsigned char> v(semantic->getData().begin(),
                                     semantic->getData().end());
        Assembly assembly = Disassemble::makeAssembly(v, address);
        DisasmDump::printInstruction(address, &assembly, pos, nullptr);
    }
}
