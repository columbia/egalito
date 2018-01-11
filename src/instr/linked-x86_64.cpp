#include <cassert>
#include <cstring>
#include "linked-x86_64.h"
#include "chunk/link.h"
#include "elf/elfspace.h"
#include "disasm/disassemble.h"
#include "disasm/makesemantic.h"  // for determineDisplacementSize
#include "operation/find.h"
#include "log/log.h"

#ifdef ARCH_X86_64
int LinkedInstruction::getDispSize() {
    return MakeSemantic::determineDisplacementSize(&*getAssembly(), opIndex);
}

unsigned LinkedInstruction::calculateDisplacement() {
    unsigned int disp = getLink()->getTargetAddress();
    if(!dynamic_cast<AbsoluteNormalLink *>(getLink())
        && !dynamic_cast<AbsoluteDataLink *>(getLink())
        && !dynamic_cast<GSTableLink *>(getLink())
        && !dynamic_cast<DistanceLink *>(getLink())) {

        disp -= (instruction->getAddress() + getSize());
    }
    return disp;
}

void LinkedInstruction::writeTo(char *target, bool useDisp) {
    auto assembly = getAssembly();
    auto dispSize = getDispSize();
    unsigned int newDisp = useDisp ? calculateDisplacement() : 0;
    int dispOffset = MakeSemantic::getDispOffset(&*assembly, opIndex);
    int i = 0;
    std::memcpy(target + i, assembly->getBytes() + i, dispOffset);
    i += dispOffset;
    std::memcpy(target + i, &newDisp, dispSize);
    i += dispSize;
    std::memcpy(target + i, assembly->getBytes() + i,
        assembly->getSize() - dispSize - dispOffset);
}

void LinkedInstruction::writeTo(std::string &target, bool useDisp) {
    auto assembly = getAssembly();
    auto dispSize = getDispSize();
    unsigned int newDisp = useDisp ? calculateDisplacement() : 0;
    int dispOffset = MakeSemantic::getDispOffset(&*assembly, opIndex);
    target.append(reinterpret_cast<const char *>(assembly->getBytes()),
        dispOffset);
    target.append(reinterpret_cast<const char *>(&newDisp), dispSize);
    target.append(reinterpret_cast<const char *>(assembly->getBytes())
        + dispOffset + dispSize,
        assembly->getSize() - dispSize - dispOffset);
}

int LinkedInstruction::getDispOffset() const {
    auto assembly = const_cast<LinkedInstruction *>(this)->getAssembly();
    return MakeSemantic::getDispOffset(&*assembly, opIndex);
}

void LinkedInstruction::regenerateAssembly() {
    // Regenerate the raw std::string representation, and then the Assembly
    // that corresponds to it, using the current Instruction address. This
    // is needed whenever the raw bytes are accessed after the link target
    // or source address changes (useful for ChunkDumper).

    std::string data;
    writeTo(data, true);
    setData(data);

    getStorage()->clearAssembly();

    setAssembly(AssemblyFactory::getInstance()->buildAssembly(
        getStorage(), instruction->getAddress()));
}

static PLTTrampoline *findPLTTrampoline(Module *module, address_t target) {
    auto pltList = module->getPLTList();
    if(!pltList) return nullptr;

    return CIter::spatial(pltList)->find(target);
}

LinkedInstruction *LinkedInstruction::makeLinked(Module *module,
    Instruction *instruction, AssemblyPtr assembly) {

    auto asmOps = assembly->getAsmOperands();
    int immIndex = -1;
    int dispIndex = -1;
    NormalLink *immLink = nullptr;
    Link *dispLink = nullptr;
    for(size_t i = 0; i < asmOps->getOpCount(); i ++) {
        const cs_x86_op *op = &asmOps->getOperands()[i];
        if(MakeSemantic::isRIPRelative(&*assembly, i)) {
            address_t target
                = (instruction->getAddress() + instruction->getSize())
                + op->mem.disp;
            auto found = CIter::spatial(module->getFunctionList())
                ->find(target);
            if(found) {
                if(found == instruction->getParent()->getParent()) {
                    dispLink = new NormalLink(found, Link::SCOPE_INTERNAL_JUMP);
                } else {
                    dispLink = new NormalLink(found, Link::SCOPE_EXTERNAL_JUMP);
                }
            }
            else {
                dispLink = LinkFactory::makeDataLink(module, target, true);
                if(!dispLink) {
                    auto c = ChunkFind().findInnermostAt(
                        module->getFunctionList(), target);
                    if(dynamic_cast<Instruction *>(c)) {
                        dispLink = new NormalLink(c, Link::SCOPE_INTERNAL_JUMP);
                    }
                    else if(auto plt = findPLTTrampoline(module, target)) {
                        // should this be a PLTLink?
                        dispLink = new NormalLink(plt, Link::SCOPE_WITHIN_MODULE);
                    }
                    else {
                        //dispLink = new UnresolvedLink(target);
                        dispLink = LinkFactory::makeMarkerLink(
                            module, target, nullptr);
                    }
                }
            }

            dispIndex = i;
        }
        else if(op->type == X86_OP_IMM) {
            auto elfMap = module->getElfSpace()->getElfMap();
            if(elfMap->isExecutable() && !elfMap->hasRelocations()) {
                address_t target = op->imm;
                auto found = CIter::spatial(module->getFunctionList())
                    ->find(target);
                if(found) {
                    immLink = new AbsoluteNormalLink(found,
                        Link::SCOPE_WITHIN_MODULE);
                    immIndex = i;
                }
            }
        }
    }

    if(immIndex < 0 && dispIndex < 0) {
        return nullptr;
    }

    auto linked = new LinkedInstruction(instruction);
    linked->setAssembly(assembly);
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
    return linked;
}

void ControlFlowInstruction::setSize(size_t value) {
    diff_t disp = value - opcode.size();
    assert(disp >= 0);
    assert(disp == 1 || disp == 2 || disp == 4);

    displacementSize = disp;
}

void ControlFlowInstruction::writeTo(char *target, bool useDisp) {
    std::memcpy(target, opcode.c_str(), opcode.size());
    diff_t disp = useDisp ? calculateDisplacement() : 0;
    std::memcpy(target + opcode.size(), &disp, displacementSize);
}

void ControlFlowInstruction::writeTo(std::string &target, bool useDisp) {
    target.append(opcode);
    diff_t disp = useDisp ? calculateDisplacement() : 0;
    target.append(reinterpret_cast<const char *>(&disp), displacementSize);
}

diff_t ControlFlowInstruction::calculateDisplacement() {
    // ControlFlowInstruction is always RIP-relative
    return getLink()->getTargetAddress()
        - (getSource()->getAddress() + getSize());
}

void StackFrameInstruction::writeTo(char *target) {
    std::memcpy(target, getStorage()->getData().c_str(), opCodeSize);
    std::memcpy(target + opCodeSize, &displacement, displacementSize);
}

void StackFrameInstruction::writeTo(std::string &target) {
    target.append(getStorage()->getData(), 0, opCodeSize);
    target.append(
        reinterpret_cast<const char *>(&displacement), displacementSize);
}

// temporary hack: one in MakeSemantic doesn't give the right size
static size_t determineDisplacementSize(Assembly *assembly) {
    if(assembly->getId() == X86_INS_MOV || assembly->getId() == X86_INS_LEA) {
        if(assembly->getSize() == 5) return 1;
    }
    LOG(1, "for " << assembly->getMnemonic());
    throw "don't know how to determined displacement size";
}

StackFrameInstruction::StackFrameInstruction(AssemblyPtr assembly) {
    getStorage()->setData(std::string(assembly->getBytes()));
    //setAssembly(assembly);

    this->id = assembly->getId();

    this->displacementSize = determineDisplacementSize(&*assembly);
    this->opCodeSize = assembly->getSize() - displacementSize;
    auto asmOps = assembly->getAsmOperands();
    for(size_t i = 0; i < asmOps->getOpCount(); i++) {
        auto op = &asmOps->getOperands()[i];
        if(op->type == X86_OP_MEM && op->mem.base == X86_REG_RSP) {
            this->displacement = op->mem.disp;
        }
    }
    LOG(10, "stackFrameInstruction : " << id);
    LOG(10, " assembly->size " << assembly->getSize());
    LOG(10, " displacementSize " << displacementSize);
    LOG(10, " opCodeSize " << opCodeSize);
    LOG(10, " displacement " << displacement);
}

void StackFrameInstruction::addToDisplacementValue(long int add) {
    displacement += add;
}

#endif
