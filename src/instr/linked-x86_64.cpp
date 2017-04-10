#include <cassert>
#include <cstring>
#include "linked-x86_64.h"
#include "chunk/link.h"
#include "elf/elfspace.h"
#include "disasm/disassemble.h"
#include "disasm/makesemantic.h"  // for determineDisplacementSize

#ifdef ARCH_X86_64
int LinkedInstruction::getDispSize() {
    return MakeSemantic::determineDisplacementSize(getAssembly());
}

unsigned LinkedInstruction::calculateDisplacement() {
    unsigned int disp = getLink()->getTargetAddress();
    if(!dynamic_cast<AbsoluteNormalLink *>(getLink())) {
        disp -= (instruction->getAddress() + getSize());
    }
    return disp;
}

void LinkedInstruction::writeTo(char *target) {
    Assembly *assembly = getAssembly();
    auto dispSize = getDispSize();
    unsigned int newDisp = calculateDisplacement();
    int dispOffset = MakeSemantic::getDispOffset(assembly, opIndex);
    int i = 0;
    std::memcpy(target + i, assembly->getBytes() + i, dispOffset);
    i += dispOffset;
    std::memcpy(target + i, &newDisp, dispSize);
    i += dispSize;
    std::memcpy(target + i, assembly->getBytes() + i,
        assembly->getSize() - dispSize - dispOffset);
}

void LinkedInstruction::writeTo(std::string &target) {
    Assembly *assembly = getAssembly();
    auto dispSize = getDispSize();
    unsigned int newDisp = calculateDisplacement();
    int dispOffset = MakeSemantic::getDispOffset(assembly, opIndex);
    target.append(reinterpret_cast<const char *>(assembly->getBytes()),
        dispOffset);
    target.append(reinterpret_cast<const char *>(&newDisp), dispSize);
    target.append(reinterpret_cast<const char *>(assembly->getBytes())
        + dispOffset + dispSize,
        assembly->getSize() - dispSize - dispOffset);
}

std::string LinkedInstruction::getData() {
    std::string data;
    writeTo(data);
    return std::move(data);
}

void LinkedInstruction::regenerateAssembly() {
    // Recreate the internal capstone data structure.
    // Useful for printing the instruction (ChunkDumper).
    std::string data = getData();
    std::vector<unsigned char> dataVector;
    for(size_t i = 0; i < data.length(); i ++) {
        dataVector.push_back(data[i]);
    }
    Assembly assembly = Disassemble::makeAssembly(
        dataVector, instruction->getAddress());

    DisassembledStorage storage(assembly);
    setStorage(std::move(storage));
}

LinkedInstruction *LinkedInstruction::makeLinked(Module *module,
    Instruction *instruction, Assembly *assembly) {

    auto asmOps = assembly->getAsmOperands();
    int immIndex = -1;
    int dispIndex = -1;
    NormalLink *immLink = nullptr;
    Link *dispLink = nullptr;
    for(size_t i = 0; i < asmOps->getOpCount(); i ++) {
        const cs_x86_op *op = &asmOps->getOperands()[i];
        if(MakeSemantic::isRIPRelative(assembly, i)) {
            address_t target
                = (instruction->getAddress() + instruction->getSize())
                + op->mem.disp;
            auto found = CIter::spatial(module->getFunctionList())
                ->find(target);
            if(found) {
                dispLink = new ExternalNormalLink(found);
            }
            else {
                dispLink = new DataOffsetLink(
                    module->getElfSpace()->getElfMap(), target);
            }

            dispIndex = i;
        }
        else if(op->type == X86_OP_IMM) {
            address_t target = op->imm;
            auto found = CIter::spatial(module->getFunctionList())
                ->find(target);
            if(found) {
                immLink = new AbsoluteNormalLink(found);
                immIndex = i;
            }
        }
    }

    auto linked = new LinkedInstruction(instruction, *assembly);
    if(immIndex >= 0 && dispIndex >= 0) {
        auto dualLink = new ImmAndDispLink(immLink, dispLink);
        linked->setIndex(-1);
        linked->setLink(dualLink);
    }
    else if(immIndex >= 0) {
        linked->setIndex(immIndex);
        linked->setLink(immLink);
    }
    else if(dispIndex >= 0) {
        linked->setIndex(dispIndex);
        linked->setLink(dispLink);
    }
    else {
        delete linked;
        return nullptr;
    }
    return linked;
}

void ControlFlowInstruction::setSize(size_t value) {
    diff_t disp = value - opcode.size();
    assert(disp >= 0);
    assert(disp == 1 || disp == 2 || disp == 4);

    displacementSize = disp;
}

void ControlFlowInstruction::writeTo(char *target) {
    std::memcpy(target, opcode.c_str(), opcode.size());
    diff_t disp = calculateDisplacement();
    std::memcpy(target + opcode.size(), &disp, displacementSize);
}
void ControlFlowInstruction::writeTo(std::string &target) {
    target.append(opcode);
    diff_t disp = calculateDisplacement();
    target.append(reinterpret_cast<const char *>(&disp), displacementSize);
}
std::string ControlFlowInstruction::getData() {
    std::string data;
    writeTo(data);
    return data;
}

diff_t ControlFlowInstruction::calculateDisplacement() {
    // ControlFlowInstruction is always RIP-relative
    return getLink()->getTargetAddress()
        - (getSource()->getAddress() + getSize());
}
#endif
