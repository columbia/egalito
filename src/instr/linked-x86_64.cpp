#include <cassert>
#include <cstring>
#include "linked-x86_64.h"
#include "chunk/link.h"
#include "elf/elfspace.h"
#include "elf/reloc.h"
#include "disasm/disassemble.h"
#include "disasm/makesemantic.h"  // for determineDisplacementSize
#include "operation/find.h"
#include "log/log.h"
#include "log/temp.h"
#include "chunk/dump.h"

#ifdef ARCH_X86_64
void LinkedInstruction::makeDisplacementInfo() {
    assert(opIndex != -1);
    auto assembly = getAssembly();
    displacementSize
        = MakeSemantic::determineDisplacementSize(&*assembly, opIndex);
    displacementOffset
        = MakeSemantic::getDispOffset(&*assembly, opIndex);
}

unsigned long LinkedInstruction::calculateDisplacement() {
    unsigned long int disp = getLink()->getTargetAddress();
    if(!dynamic_cast<AbsoluteNormalLink *>(getLink())
        && !dynamic_cast<AbsoluteDataLink *>(getLink())
        && !dynamic_cast<AbsoluteMarkerLink *>(getLink())
        && !dynamic_cast<GSTableLink *>(getLink())
        && !dynamic_cast<DistanceLink *>(getLink())) {

        disp -= (instruction->getAddress() + getSize());
    }
    return disp;
}

void LinkedInstruction::writeTo(char *target, bool useDisp) {
    auto assembly = getAssembly();
    auto dispSize = getDispSize();
    unsigned long int newDisp = useDisp ? calculateDisplacement() : 0;
    int dispOffset = getDispOffset();
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
    unsigned long int newDisp = useDisp ? calculateDisplacement() : 0;
    int dispOffset = getDispOffset();
    target.append(reinterpret_cast<const char *>(assembly->getBytes()),
        dispOffset);
    target.append(reinterpret_cast<const char *>(&newDisp), dispSize);
    target.append(reinterpret_cast<const char *>(assembly->getBytes())
        + dispOffset + dispSize,
        assembly->getSize() - dispSize - dispOffset);
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
    Instruction *instruction, AssemblyPtr assembly, Reloc *reloc) {

    size_t offset = reloc->getAddress() - instruction->getAddress();
    auto index = MakeSemantic::getOpIndex(&*assembly, offset);

    bool relative = MakeSemantic::isRIPRelative(&*assembly, index);
    auto link
        = PerfectLinkResolver().resolveInternally(reloc, module, true, relative);
    if(!link) return nullptr;

    auto linked = new LinkedInstruction(instruction);
    linked->setAssembly(assembly);
    linked->setIndex(index);
    linked->setLink(link);
    return linked;
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
            assert(!dispLink);
            address_t target
                = (instruction->getAddress() + instruction->getSize())
                + op->mem.disp;
            Chunk *found = CIter::spatial(module->getFunctionList())
                ->findContaining(target);
            if(!found && module->getPLTList()) {
                found = CIter::spatial(module->getPLTList())
                    ->find(target);
            }
            if(found) {
                auto scope = (found == instruction->getParent()->getParent()) ?
                    Link::SCOPE_INTERNAL_JUMP : Link::SCOPE_EXTERNAL_JUMP;
                if(found->getAddress() != target) {
                    auto function = dynamic_cast<Function *>(found);
                    if(function) {
                        found = ChunkFind().findInnermostInsideInstruction(
                            function, target);
                    }
                }
                dispLink = new NormalLink(found, scope);
            }
            else {
                auto c = ChunkFind().findInnermostAt(
                    module->getFunctionList(), target);
                if(dynamic_cast<Instruction *>(c)) {
                    dispLink = new NormalLink(c, Link::SCOPE_INTERNAL_JUMP);
                }
                else if(auto plt = findPLTTrampoline(module, target)) {
                    // should this be a PLTLink?
                    dispLink = new NormalLink(plt, Link::SCOPE_WITHIN_MODULE);
                }
                if(!dispLink) {
                    dispLink = LinkFactory::makeDataLink(module, target, true);
                }
                if(!dispLink) {
                    dispLink = LinkFactory::makeInferredMarkerLink(module,
                        target, true);
                    if(!dispLink) {
                        ChunkDumper d;
                        LOG(1, "making inferred marker link failed "
                            << module->getName()
                            << " " << std::hex << instruction->getAddress());
                        LOG(1, "target is "<< std::hex << target);
                        module->getDataRegionList()->accept(&d);
                    }
                }
                if(!dispLink) {
                    dispLink = new UnresolvedLink(target);
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
