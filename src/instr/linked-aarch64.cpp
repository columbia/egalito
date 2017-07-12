#include <cstring>  // for memcpy
#include "linked-aarch64.h"
#include "instr.h"
#include "analysis/slicingtree.h"
#include "analysis/controlflow.h"
#include "analysis/slicing.h"
#include "analysis/slicingmatch.h"
#include "analysis/dataflow.h"
#include "analysis/liveregister.h"
#include "analysis/pointerdetection.h"
#include "chunk/concrete.h"
#include "chunk/link.h"
#include "disasm/disassemble.h"
#include "elf/elfspace.h"
#include "operation/find.h"
#include "util/streamasstring.h"

#include "log/log.h"
#include "log/temp.h"

#if defined(ARCH_AARCH64)
LinkedInstruction::LinkedInstruction(Instruction *source,
    const Assembly &assembly)
    : LinkDecorator<DisassembledInstruction>(assembly), source(source),
    modeInfo(&AARCH64_ImInfo[getMode(assembly)]) {
}

const LinkedInstruction::AARCH64_modeInfo_t LinkedInstruction::AARCH64_ImInfo[AARCH64_IM_MAX] = {

      /* ADRP */
      {0x9000001F,
       [] (address_t dest, address_t src, uint32_t fixed) {
           diff_t disp = dest - (src & ~0xFFF);
           uint32_t imm = disp >> 12;
           return (((imm & 0x3) << 29) | ((imm & 0x1FFFFC) << 3)); },
       1},
      /* ADR */
      {0x9F00001F,
       [] (address_t dest, address_t src, uint32_t fixed) {
           diff_t disp = dest - src;
           uint32_t imm = disp >> 12;
           return (((imm & 0x3) << 29) | ((imm & 0x1FFFFC) << 3)); },
       1},
      /* ADDIMM (in combination with ADRP) */
      {0xFFC003FF,
       [] (address_t dest, address_t src, uint32_t fixed) {
           diff_t disp = dest & 0xFFF;
           uint32_t imm = disp << 10;
           return (imm & ~0xFFC003FF); },
       2
      },
      /* LDR (immediate: unsigned offset, with ADRP) */
      {0xFFE003FF,
       [] (address_t dest, address_t src, uint32_t fixed) {
           diff_t disp = dest & 0xFFF;
           int scale = fixed >> 30;
           uint32_t imm = (disp >> scale) << 10;
           return (imm & ~0xFFE003FF); },
       1
      },
      /* LDRH (immediate: unsigned offset, with ADRP) */
      {0xFFE003FF,
       [] (address_t dest, address_t src, uint32_t fixed) {
           diff_t disp = dest & 0xFFF;
           uint32_t imm = (disp >> 1) << 10;
           return (imm & ~0xFFE003FF); },
       1
      },
      /* LDRB (immediate: unsigned offset, with ADRP) */
      {0xFFE003FF,
       [] (address_t dest, address_t src, uint32_t fixed) {
           diff_t disp = dest & 0xFFF;
           uint32_t imm = disp << 10;
           return (imm & ~0xFFE003FF); },
       1
      },
      /* LDRSW (immediate: unsigned offset, with ADRP) */
      {0xFFE003FF,
       [] (address_t dest, address_t src, uint32_t fixed) {
           diff_t disp = dest & 0xFFF;
           uint32_t imm = (disp >> 2) << 10;
           return (imm & ~0xFFE003FF); },
       1
      },
      /* LDRSH (immediate: unsigned offset, with ADRP) */
      {0xFFE003FF,
       [] (address_t dest, address_t src, uint32_t fixed) {
           diff_t disp = dest & 0xFFF;
           uint32_t imm = (disp >> 1) << 10;
           return (imm & ~0xFFE003FF); },
       1
      },
      /* LDRSB (immediate: unsigned offset, with ADRP) */
      {0xFFE003FF,
       [] (address_t dest, address_t src, uint32_t fixed) {
           diff_t disp = dest & 0xFFF;
           uint32_t imm = disp << 10;
           return (imm & ~0xFFE003FF); },
       1
      },
      /* STR (immediate: unsigned offset, with ADRP) */
      {0xFFE003FF,
       [] (address_t dest, address_t src, uint32_t fixed) {
           diff_t disp = dest & 0xFFF;
           int scale = fixed >> 30;
           uint32_t imm = (disp >> scale) << 10;
           return (imm & ~0xFFE003FF); },
       1
      },
      /* STRH (immediate: unsigned offset, with ADRP) */
      {0xFFE003FF,
       [] (address_t dest, address_t src, uint32_t fixed) {
           diff_t disp = dest & 0xFFF;
           uint32_t imm = (disp >> 1) << 10;
           return (imm & ~0xFFE003FF); },
       1
      },
      /* STRB (immediate: unsigned offset, with ADRP) */
      {0xFFE003FF,
       [] (address_t dest, address_t src, uint32_t fixed) {
           diff_t disp = dest & 0xFFF;
           uint32_t imm = disp << 10;
           return (imm & ~0xFFE003FF); },
       1
      },
      /* BL <label> */
      {0xFC000000,
       [] (address_t dest, address_t src, uint32_t fixed) {
           diff_t disp = dest - src;
           uint32_t imm = disp >> 2;
           return (imm & ~0xFC000000); },
       0
      },
      /* B <label> (same as BL; keep it separate for debugging purpose) */
      {0xFC000000,
       [] (address_t dest, address_t src, uint32_t fixed) {
           diff_t disp = dest - src;
           uint32_t imm = disp >> 2;
           return (imm & ~0xFC000000); },
       0
      },
      /* B.COND <label> */
      {0xFF00001F,
       [] (address_t dest, address_t src, uint32_t fixed) {
           diff_t disp = dest - src;
           uint32_t imm = disp >> 2;
           return ((imm << 5)& ~0xFF00001F); },
       0
      },

      /* CBZ <Xt>, <label> */
      {0xFF00001F,
       [] (address_t dest, address_t src, uint32_t fixed) {
           diff_t disp = dest - src;
           uint32_t imm = disp >> 2;
           return ((imm << 5)& ~0xFF00001F); },
       1
      },
      /* CBNZ <Xt>, <label> */
      {0xFF00001F,
       [] (address_t dest, address_t src, uint32_t fixed) {
           diff_t disp = dest - src;
           uint32_t imm = disp >> 2;
           return ((imm << 5)& ~0xFF00001F); },
       1
      },
      /* TBZ <Xt>, #<imm>, <label> */
      {0xFFF8001F,
       [] (address_t dest, address_t src, uint32_t fixed) {
           diff_t disp = dest - src;
           uint32_t imm = disp >> 2;
           return ((imm << 5)& ~0xFFF8001F); },
       2
      },
      /* TBNZ <Xt>, #<imm>, <label> */
      {0xFFF8001F,
       [] (address_t dest, address_t src, uint32_t fixed) {
           diff_t disp = dest - src;
           uint32_t imm = disp >> 2;
           return ((imm << 5)& ~0xFFF8001F); },
       2
      },
};

uint32_t LinkedInstruction::rebuild() {
    uint32_t fixedBytes;
    std::memcpy(&fixedBytes, getAssembly()->getBytes(), 4);
    fixedBytes &= modeInfo->fixedMask;

    address_t dest = getLink()->getTargetAddress();
    uint32_t imm =
        getModeInfo()->makeImm(dest, getSource()->getAddress(), fixedBytes);
#if 0
    LOG(1, "mode: " << getModeInfo() - AARCH64_ImInfo);
    LOG(1, "src: " << getSource()->getAddress());
    LOG(1, "dest: " << dest);
    LOG(1, "fixedBytes: " << fixedBytes);
    LOG(1, "imm: " << imm);
    LOG(1, "result: " << (fixedBytes | imm));
#endif
    return fixedBytes | imm;
}

uint32_t LinkedInstruction::getOriginalOffset() const {
    auto operands = const_cast<LinkedInstruction *>(this)
        ->getAssembly()->getAsmOperands()->getOperands();
    if(operands[modeInfo->immediateIndex].type == ARM64_OP_IMM) {
        return operands[modeInfo->immediateIndex].imm;
    }
    else {  // mem for LDR x0, [x0,#4048]
        return operands[modeInfo->immediateIndex].mem.disp;
    }
}

void LinkedInstruction::writeTo(char *target, bool useDisp) {
    *reinterpret_cast<uint32_t *>(target) = rebuild();
}

void LinkedInstruction::writeTo(std::string &target, bool useDisp) {
    uint32_t data = rebuild();
    target.append(reinterpret_cast<const char *>(&data), getSize());
}

LinkedInstruction::Mode LinkedInstruction::getMode(const Assembly &assembly) {
    LinkedInstruction::Mode m;
    switch(assembly.getId()) {
    case ARM64_INS_B:
        if(assembly.getBytes()[3] == 0x54) {
            m = AARCH64_IM_BCOND;
        }
        else {
            m = AARCH64_IM_B;
        }
        break;
    case ARM64_INS_BL:      m = AARCH64_IM_BL;      break;
    case ARM64_INS_CBZ:     m = AARCH64_IM_CBZ;     break;
    case ARM64_INS_CBNZ:    m = AARCH64_IM_CBNZ;    break;
    case ARM64_INS_TBZ:     m = AARCH64_IM_TBZ;     break;
    case ARM64_INS_TBNZ:    m = AARCH64_IM_TBNZ;    break;
    case ARM64_INS_ADRP:    m = AARCH64_IM_ADRP;    break;
    case ARM64_INS_ADR:     m = AARCH64_IM_ADR;     break;
    case ARM64_INS_ADD:     m = AARCH64_IM_ADDIMM;  break;
    case ARM64_INS_LDR:     m = AARCH64_IM_LDR;     break;
    case ARM64_INS_LDRH:    m = AARCH64_IM_LDRH;    break;
    case ARM64_INS_LDRB:    m = AARCH64_IM_LDRB;    break;
    case ARM64_INS_LDRSB:   m = AARCH64_IM_LDRSB;   break;
    case ARM64_INS_LDRSW:   m = AARCH64_IM_LDRSW;   break;
    case ARM64_INS_LDRSH:   m = AARCH64_IM_LDRSH;   break;
    case ARM64_INS_STR:     m = AARCH64_IM_STR;     break;
    case ARM64_INS_STRH:    m = AARCH64_IM_STRH;    break;
    case ARM64_INS_STRB:    m = AARCH64_IM_STRB;    break;
    default:
        throw (StreamAsString() << "mnemonic " << assembly.getMnemonic()
            << " not yet implemented in LinkedInstruction")
            .operator std::string();
    }
    return m;
}

void LinkedInstruction::regenerateAssembly() {
    auto data = AARCH64InstructionBinary(rebuild());
    Assembly assembly = Disassemble::makeAssembly(
        data.getVector(), getSource()->getAddress());
    getStorage().setAssembly(std::move(assembly));
}

void LinkedInstruction::makeAllLinked(Module *module) {
    DataFlow df;
    LiveRegister live;
    PointerDetection pd;
    for(auto func : CIter::functions(module)) {
        df.addUseDefFor(func);
    }
    for(auto func : CIter::functions(module)) {
        live.detect(func);
    }
    for(auto func : CIter::functions(module)) {
        df.adjustCallUse(&live, func, module);
    }
    for(auto func : CIter::functions(module)) {
        pd.detect(df.getWorkingSet(func));
    }

    //TemporaryLogLevel tll("instr", 10);
    for(auto [instruction, address] : pd.getList()) {
        LOG(9, "pointer at 0x" << std::hex << instruction->getAddress()
            << " pointing to 0x" << address);
        auto assembly = instruction->getSemantic()->getAssembly();
        auto linked = new LinkedInstruction(instruction, *assembly);

        Chunk *found = CIter::spatial(module->getFunctionList())->find(address);
        Link *link = nullptr;
        if(found) {
            LOG(10, " ==> " << found->getName());
            link = new ExternalNormalLink(found);
        }
        else {
            auto f = dynamic_cast<Function *>(
                instruction->getParent()->getParent());

            found = ChunkFind().findInnermostAt(f, address);
            if(found) {
                link = new NormalLink(found);
            }
            else {
                LOG(10, " --> data link");
                link = LinkFactory::makeDataLink(module, address, true);
                if(!link) {
                    throw "failed to create link!";
                }
            }
        }
        linked->setLink(link);
        auto v = instruction->getSemantic();
        instruction->setSemantic(linked);
        delete v;
    }
}
#endif
