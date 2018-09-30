#include <iostream>
#include <sstream>
#include <cstdio>
#include "dump.h"
#include "analysis/jumptable.h"
#include "disasm/dump.h"
#include "disasm/disassemble.h"
#include "instr/writer.h"
#include "elf/symbol.h"
#include "log/log.h"

void ChunkDumper::visit(Module *module) {
    size_t count = 0;
    if(auto functionList = module->getFunctionList()) {
        count = functionList->getChildren()->getIterable()->getCount();
    }
    LOG(4, "=== [" << module->getName() << "] with " << count << " functions ===");
    recurse(module);
}
void ChunkDumper::visit(FunctionList *functionList) {
    recurse(functionList);
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
void ChunkDumper::visit(VTableList *vtableList) {
    LOG(1, "--[vtables]--");
    recurse(vtableList);
}
void ChunkDumper::visit(ExternalSymbolList *externalSymbolList) {
    LOG(1, "--[external-symbols]--");
    recurse(externalSymbolList);
}
void ChunkDumper::visit(LibraryList *libraryList) {
    LOG(1, "--[libraries]--");
    recurse(libraryList);
}

void ChunkDumper::visit(Function *function) {
    LOG(4, "---[" << function->getName() << "]---");
    recurse(function);
}

void ChunkDumper::visit(Block *block) {
    if(showBasicBlocks) LOG(4, block->getName() << ":");
    recurse(block);
}

void ChunkDumper::visit(Instruction *instruction) {
    int pos = INT_MIN;
    auto parent = instruction->getParent();
    if(!showBasicBlocks && parent) parent = parent->getParent();
    if(parent) {
        auto currentPos = instruction->getPosition();
        auto parentPos = parent->getPosition();
        if(currentPos && parentPos) {
            pos = currentPos->get() - parentPos->get();
        }
    }

    CLOG0(4, "    ");

    InstrDumper instrDumper(instruction->getAddress(), pos);
    instruction->getSemantic()->accept(&instrDumper);
}

void ChunkDumper::visit(PLTTrampoline *trampoline) {
    LOG(4, "---[" << trampoline->getName() << "]---");
    LOG(4, "    plt size: " << trampoline->getSize() << " (standard size: " << PLTList::getPLTTrampolineSize() << ")");
    recurse(trampoline);
}

void ChunkDumper::visit(JumpTable *jumpTable) {
    LOG(1, "jump table in ["
        << jumpTable->getFunction()->getName() << "] at 0x"
        << std::hex << jumpTable->getAddress() << " with "
        << std::dec << jumpTable->getEntryCount()
        << " entries");
    auto d = jumpTable->getDescriptor();
    LOG(3, "  target base address = "
        << std::hex << d->getTargetBaseLink()->getTargetAddress());
    LOG(3, "  scale = " << std::hex << d->getScale());
    recurse(jumpTable);
}

void ChunkDumper::visit(JumpTableEntry *jumpTableEntry) {
    LOG0(10, "    " << std::hex << jumpTableEntry->getAddress());
    if(auto link = jumpTableEntry->getLink()) {
        LOG(10, " => " << link->getTargetAddress());
    }
}

void ChunkDumper::visit(DataRegion *dataRegion) {
    LOG(1, "---[" << dataRegion->getName() << "]---");
    LOG(1, std::hex <<
        dataRegion->getAddress() << " + " << dataRegion->getSize());
    for(auto sec : CIter::children(dataRegion)) {
        LOG(1, "[" << sec->getAddress() << ", "
            << (sec->getAddress() + sec->getSize())
            << ") " << sec->getName());
    }
    recurse(dataRegion);
}

void ChunkDumper::visit(DataSection *dataSection) {
    LOG(10, "inside " << dataSection->getName() << ":");
    for(auto var : CIter::children(dataSection)) {
        auto target = var->getDest()->getTarget();
        LOG0(10, "var: " << var->getAddress());
        if(target) {
            LOG(10, " --> " << target->getName());
        }
        else LOG(10, "");
    }
}

void ChunkDumper::visit(DataVariable *dataVariable) {
    LOG0(1, "data variable at " << dataVariable->getAddress());
    auto target = dataVariable->getDest()->getTarget();
    if(target) {
        LOG(1, " --> " << target->getName());
    }
    else LOG(1, "");
}

void ChunkDumper::visit(MarkerList *markerList) {
    LOG(1, "--[markers]--");
    for(auto marker : CIter::children(markerList)) {
        LOG(1, "Marker at address 0x" << std::hex << marker->getAddress());
    }
}

void ChunkDumper::visit(VTable *vtable) {
    LOG(1, vtable->getName());
    recurse(vtable);
}

void ChunkDumper::visit(VTableEntry *vtableEntry) {
    if(auto target = vtableEntry->getLink()->getTarget()) {
        LOG(1, " " << std::hex << vtableEntry->getLink()->getTargetAddress()
            << " " << target->getName());
    }
    else {
        LOG(1, " " << std::hex << vtableEntry->getLink()->getTargetAddress());
    }
}

void ChunkDumper::visit(ExternalSymbol *externalSymbol) {
    LOG(1, "external ref for \"" << externalSymbol->getName()
        << "\" type " << static_cast<int>(externalSymbol->getType())
        << " bind " << static_cast<int>(externalSymbol->getBind())
        << " resolved to 0x" << std::hex << externalSymbol->getResolved());
}

void ChunkDumper::visit(Library *library) {
    LOG(1, "library \"" << library->getName() << "\"");
    if(library->getModule()) {
        LOG(1, "    loaded as " << library->getModule()->getName() << " from "
            << library->getResolvedPath());
    }
}

void InstrDumper::visit(IsolatedInstruction *semantic) {
    auto assembly = semantic->getAssembly();
    DisasmDump::printInstruction(address, &*assembly, pos, nullptr);
}

void InstrDumper::visit(LinkedInstruction *semantic) {
    dumpLinkedBase(semantic, false);
}

void InstrDumper::dumpLinkedBase(LinkedInstructionBase *semantic, bool isCF) {
    semantic->regenerateAssembly();
    auto assembly = semantic->getAssembly();
    auto link = semantic->getLink();
    auto target = link ? link->getTarget() : nullptr;
    if(auto v = dynamic_cast<GSTableLink *>(link)) {
        std::ostringstream targetName;
        targetName << target->getName() << "@gs["
            << v->getEntry()->getIndex() << "]";
        DisasmDump::printInstruction(
            address, &*assembly, pos, targetName.str().c_str());
        return;
    }
    if(isCF) {
        std::ostringstream name;
#ifdef ARCH_X86_64
        if(semantic->getAssembly()->getMnemonic() == "callq") name << "(CALL)";
#elif defined(ARCH_AARCH64)
        if(semantic->getAssembly()->getMnemonic() == "bl") name << "(CALL)";
#elif defined(ARCH_ARM)
        if(semantic->getAssembly()->getMnemonic() == "bl"
            || semantic->getAssembly()->getMnemonic() == "blx") name << "(CALL)";
#endif
        else {
            name << "(JUMP " << semantic->getAssembly()->getMnemonic() << ")";
            //name << " [opcode size " << semantic->getOpcode().length() << ", dispSize " << semantic->getDisplacementSize() << "] ";
        }
        std::string bytes = getBytes(semantic);
        std::string bytes2 = DisasmDump::formatBytes(bytes.c_str(), bytes.size());
        DisasmDump::printInstructionRaw(address,
            pos, name.str().c_str(),
            semantic->getAssembly()->getOpStr().c_str(), nullptr, bytes2.c_str(),
            false);
    }
    else {
        if(target) {
            DisasmDump::printInstruction(
                address, &*assembly, pos, target->getName().c_str());
        }
        else {
            unsigned long targetAddress = link->getTargetAddress();
            DisasmDump::printInstructionCalculated(
                address, &*assembly, pos, targetAddress);
        }
    }
}

void InstrDumper::visit(ControlFlowInstruction *semantic) {
    dumpControlFlow(semantic, false);
}

void InstrDumper::visit(DataLinkedControlFlowInstruction *semantic) {
    dumpLinkedBase(semantic, true);
}

void InstrDumper::dumpControlFlow(ControlFlowInstructionBase *semantic, bool printStar) {
    auto link = semantic->getLink();
    auto target = link ? link->getTarget() : nullptr;

    std::ostringstream targetName;
    if(auto v = dynamic_cast<PLTLink *>(link)) {
        targetName << v->getPLTTrampoline()->getName();
    }
    else if(auto v = dynamic_cast<SymbolOnlyLink *>(link)) {
        targetName << v->getSymbol()->getName() << "@symonly";
    }
    else if(target) {
        if(target->getName() != "???") {
            targetName << target->getName().c_str();
        }
        else {
            targetName << "target-" << std::hex << &target;
        }
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

    std::string bytes = getBytes(semantic);
    std::string bytes2 = DisasmDump::formatBytes(bytes.c_str(), bytes.size());

    DisasmDump::printInstructionRaw(address,
        pos,
        name.str().c_str(),
        link ? link->getTargetAddress() : 0,
        printStar,
        targetName.str().c_str(),
        bytes2.c_str());
}

void InstrDumper::visit(IndirectJumpInstruction *semantic) {
    std::ostringstream name;
    name << "(JUMP* " << semantic->getMnemonic() << ")";

    std::string bytes = getBytes(semantic);
    std::string bytes2 = DisasmDump::formatBytes(bytes.c_str(), bytes.size());

    std::string jumpTableDescription;
    if(semantic->isForJumpTable()) {
        auto jumpTable = semantic->getJumpTables()[0];
        std::ostringstream tableStream;
        tableStream << "jumptable@" << std::hex << jumpTable->getAddress()
            << ",entries=" << std::dec << jumpTable->getEntryCount();
        jumpTableDescription = tableStream.str();
    }

    DisasmDump::printInstructionRaw(address,
        pos, name.str().c_str(),
        semantic->getAssembly()->getOpStr().c_str(),
        semantic->isForJumpTable() ? jumpTableDescription.c_str() : nullptr,
        bytes2.c_str(),
        false);
}

void InstrDumper::visit(IndirectCallInstruction *semantic) {
    std::string bytes = getBytes(semantic);
    std::string bytes2 = DisasmDump::formatBytes(bytes.c_str(), bytes.size());

    DisasmDump::printInstructionRaw(address,
        pos, "(CALL*)",
        semantic->getAssembly()->getOpStr().c_str(), nullptr, bytes2.c_str(),
        false);
}

void InstrDumper::visit(StackFrameInstruction *semantic) {
#ifdef ARCH_X86_64
    std::string data = getBytes(semantic);
    std::vector<unsigned char> v(data.begin(), data.end());
    auto assembly = Disassemble::makeAssembly(v, address);
    DisasmDump::printInstruction(address, &assembly, pos, nullptr);
#endif
}

void InstrDumper::visit(LiteralInstruction *semantic) {
    std::string bytes = getBytes(semantic);
    std::string bytes2 = DisasmDump::formatBytes(bytes.c_str(), bytes.size());

    DisasmDump::printInstructionRaw(address,
        pos, "(literal)", "", nullptr, bytes2.c_str(), false);
}

void InstrDumper::visit(LinkedLiteralInstruction *semantic) {
#ifdef ARCH_AARCH64
    auto link = semantic->getLink();
    std::string bytes = getBytes(semantic);
    std::string bytes2 = DisasmDump::formatBytes(bytes.c_str(), bytes.size());

    DisasmDump::printInstructionRaw(address,
        pos,
        "(literal)",
        link ? link->getTargetAddress() : 0,
        nullptr,
        bytes2.c_str());
#endif
}

std::string InstrDumper::getBytes(InstructionSemantic *semantic) {
    InstrWriterGetData writer;
    semantic->accept(&writer);
    return std::move(writer.get());
}
