#include <capstone/capstone.h>
#include "promotejumps.h"
#include "operation/mutator.h"
#include "instr/concrete.h"
#include "log/log.h"

void PromoteJumpsPass::visit(Instruction *instruction) {
#ifdef ARCH_X86_64
    auto v = dynamic_cast<ControlFlowInstruction *>(instruction->getSemantic());
    if(!v) return;

    if(!v->getLink()) return;

    address_t disp = v->calculateDisplacement();
    if(v->getDisplacementSize() == 1) {
        if(!fitsIn<signed char>(disp)) {
            promote(instruction);
        }
        else if(dynamic_cast<ExternalNormalLink *>(v->getLink())
            || dynamic_cast<ExternalOffsetLink *>(v->getLink())) {

            promote(instruction);
        }
    }

    if(!fitsIn<signed int>(disp)) {
        LOG(1, "Error: displacement in " << instruction->getName()
            << " is too large for 32-bit reach: " << std::hex << disp);
        std::abort();
    }
#endif
}

void PromoteJumpsPass::promote(Instruction *instruction) {
#ifdef ARCH_X86_64
    LOG(1, "Promote jump instruction " << instruction->getName());
    auto v = dynamic_cast<ControlFlowInstruction *>(instruction->getSemantic());
    LOG(1, "    target before = " << v->getLink()->getTargetAddress());

    size_t oldSize = v->getSize();

    v->setOpcode(getWiderOpcode(v->getId()));
    v->setDisplacementSize(4);

    ChunkMutator(instruction->getParent())
        .modifiedChildSize(instruction, v->getSize() - oldSize);

    LOG(1, "    target after = " << v->getLink()->getTargetAddress());
#endif
}

std::string PromoteJumpsPass::getWiderOpcode(unsigned int id) {
    std::string opcode;
#define WRITE_BYTE(b) opcode += static_cast<unsigned char>(b)
    switch(id) {
    case X86_INS_JMP:     WRITE_BYTE(0xe9); break;
    case X86_INS_JA:      WRITE_BYTE(0x0f); WRITE_BYTE(0x87); break;
    case X86_INS_JAE:     WRITE_BYTE(0x0f); WRITE_BYTE(0x83); break;
    case X86_INS_JB:      WRITE_BYTE(0x0f); WRITE_BYTE(0x82); break;
    case X86_INS_JBE:     WRITE_BYTE(0x0f); WRITE_BYTE(0x86); break;
    case X86_INS_JG:      WRITE_BYTE(0x0f); WRITE_BYTE(0x8f); break;
    case X86_INS_JGE:     WRITE_BYTE(0x0f); WRITE_BYTE(0x8d); break;
    case X86_INS_JL:      WRITE_BYTE(0x0f); WRITE_BYTE(0x8c); break;
    case X86_INS_JLE:     WRITE_BYTE(0x0f); WRITE_BYTE(0x8e); break;
    case X86_INS_JNO:     WRITE_BYTE(0x0f); WRITE_BYTE(0x81); break;
    case X86_INS_JNP:     WRITE_BYTE(0x0f); WRITE_BYTE(0x8b); break;
    case X86_INS_JNS:     WRITE_BYTE(0x0f); WRITE_BYTE(0x89); break;
    case X86_INS_JO:      WRITE_BYTE(0x0f); WRITE_BYTE(0x80); break;
    case X86_INS_JP:      WRITE_BYTE(0x0f); WRITE_BYTE(0x8a); break;
    case X86_INS_JS:      WRITE_BYTE(0x0f); WRITE_BYTE(0x88); break;
    case X86_INS_JE:      WRITE_BYTE(0x0f); WRITE_BYTE(0x84); break;
    case X86_INS_JNE:     WRITE_BYTE(0x0f); WRITE_BYTE(0x85); break;
    case X86_INS_JCXZ:
    case X86_INS_JRCXZ:
    case X86_INS_JECXZ:
        // TODO: handle properly
        LOG(1, "Can't promote JRCXZ or JECXZ right now, always short.");
    default:
        LOG(1, "Unknown jump opcode id encountered: " << id);
        break;
    }
#undef WRITE_BYTE
    return std::move(opcode);
}
