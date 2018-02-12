#include <cstring>  // for memcpy
#include <cassert>
#include <fstream>
#include "linked-aarch64.h"
#include "config.h"
#include "instr/instr.h"
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
#include "operation/find2.h"
#include "util/streamasstring.h"

#include "log/log.h"
#include "log/temp.h"

#if defined(ARCH_AARCH64)
LinkedInstruction::LinkedInstruction(Instruction *instruction)
    : instruction(instruction), modeInfo(nullptr) {
}

void LinkedInstruction::setAssembly(AssemblyPtr assembly) {
    modeInfo = &AARCH64_ImInfo[getMode(*assembly)];
    LinkDecorator<SemanticImpl>::setAssembly(assembly);
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
           uint32_t imm = disp;
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
           int scale = (fixed & 0x00800000)>>21| fixed >> 30;
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
      /* LDR (literal) */
      {0xFF00001F,
       [] (address_t dest, address_t src, uint32_t fixed) {
           diff_t disp = (dest - src) & 0x7FFFF;
           uint32_t imm = (disp >> 2) << 5;
           return (imm & ~0xFF00001F); },
       1
      },
      /* MOV (wide immediate) */
      {0xFFE0001F,
       [] (address_t dest, address_t src, uint32_t fixed) {
           diff_t disp = dest & 0xFFFF;
           uint32_t imm = disp << 5;
           return (imm & ~0xFFE0001F); },
       1
      },
      /* MOVK */
      {0xFFE0001F,
       [] (address_t dest, address_t src, uint32_t fixed) {
           auto hw = (fixed >> 21u) & 0x3u;
           diff_t disp = (dest >> (hw << 4)) & 0xFFFF;
           uint32_t imm = disp << 5;
           return (imm & ~0xFFE0001F); },
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
    std::memcpy(&fixedBytes, &getData()[0], 4);
    fixedBytes &= modeInfo->fixedMask;

    address_t dest = getLink()->getTargetAddress();
    uint32_t imm =
        getModeInfo()->makeImm(dest, getSource()->getAddress(), fixedBytes);
#if 0
    const int ll = 10;
    LOG(ll, "mode: " << getModeInfo() - AARCH64_ImInfo);
    LOG(ll, "src: " << getSource()->getAddress());
    LOG(ll, "dest: " << dest);
    LOG(ll, "fixedBytes: " << fixedBytes);
    LOG(ll, "imm: " << imm);
    LOG(ll, "result: " << (fixedBytes | imm));
#endif
    return fixedBytes | imm;
}

// only works before move
bool LinkedInstruction::check() {
    uint32_t original;
    std::memcpy(&original, &getData()[0], 4);

    uint32_t rebuilt = rebuild();
    if(original != rebuilt) {
        LOG(10, "original: " << std::hex << original);
        TemporaryLogLevel tll("instr", 11);
        rebuilt = rebuild();
        assert(original == rebuilt);
    }
    return true;
}

int64_t LinkedInstruction::getOriginalOffset() const {
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
    case ARM64_INS_LDR:
        if((assembly.getBytes()[3] & 0x04) == 0x00) { // INT
            if(assembly.getBytes()[3] & 0x80) {
                m = AARCH64_IM_LDRIMM;
                if(!(assembly.getBytes()[3] & 0x01)) {
                    assert("post-index or pre-index LDR with IMM?" && 0);
                }
            }
            else {
                m = AARCH64_IM_LDRLIT;
            }
        }
        else {  // FP
            if(assembly.getBytes()[3] & 0x20) {
                m = AARCH64_IM_LDRIMM;
                if(!(assembly.getBytes()[3] & 0x01)) {
                    assert("post-index or pre-index LDR with IMM?" && 0);
                }
            }
            else {
                m = AARCH64_IM_LDRLIT;
            }
        }
        break;
    case ARM64_INS_LDRH:    m = AARCH64_IM_LDRH;    break;
    case ARM64_INS_LDRB:    m = AARCH64_IM_LDRB;    break;
    case ARM64_INS_LDRSB:   m = AARCH64_IM_LDRSB;   break;
    case ARM64_INS_LDRSW:   m = AARCH64_IM_LDRSW;   break;
    case ARM64_INS_LDRSH:   m = AARCH64_IM_LDRSH;   break;
    case ARM64_INS_MOV:     m = AARCH64_IM_MOV;     break;
    case ARM64_INS_MOVK:    m = AARCH64_IM_MOVK;    break;
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
    std::string data;
    writeTo(data, true);
    setData(data);

    getStorage()->clearAssembly();

    setAssembly(AssemblyFactory::getInstance()->buildAssembly(
        getStorage(), instruction->getAddress()));
}

LinkedInstruction *LinkedInstruction::makeLinked(Module *module,
    Instruction *instruction, AssemblyPtr assembly, Reloc *reloc,
    bool resolveWeak) {

    auto link
        = PerfectLinkResolver().resolveInternally(reloc, module, resolveWeak);
    if(link) {
        auto linked = new LinkedInstruction(instruction);
        linked->setLink(link);
        linked->setAssembly(assembly);
        return linked;
    }

    return nullptr;
}

LinkedLiteralInstruction *LinkedLiteralInstruction::makeLinked(Module *module,
    Instruction *instruction, std::string raw, Reloc *reloc, bool resolveWeak) {

    auto link
        = PerfectLinkResolver().resolveInternally(reloc, module, resolveWeak);
    if(link) {
        auto linked = new LinkedLiteralInstruction();
        linked->setData(raw);
        linked->setLink(link);
        return linked;
    }

    return nullptr;
}

void LinkedInstruction::makeAllLinked(Module *module) {
    std::vector<std::pair<Instruction *, address_t>>&& list
        = loadFromFile(module);

    if(list.size() > 0) {
        resolveLinks(module, list);
    } else {
        DataFlow df;
        LiveRegister live;
        PointerDetection pd;
        for(auto func : CIter::functions(module)) {
            df.addUseDefFor(func);
        }
        for(auto func : CIter::functions(module)) {
            live.detect(df.getWorkingSet(func));
        }
        for(auto func : CIter::functions(module)) {
            df.adjustCallUse(&live, func, module);
        }
        for(auto func : CIter::functions(module)) {
            pd.detect(df.getWorkingSet(func));
        }

        resolveLinks(module, pd.getList());
        saveToFile(module, pd.getList());
    }

    for(auto f : CIter::functions(module)) {
        for(auto b : CIter::children(f)) {
            for(auto i : CIter::children(b)) {
                if(i->getSize() != sizeof(address_t)) continue;
                auto v = dynamic_cast<LiteralInstruction *>(i->getSemantic());
                if(!v) continue;

                uint64_t target;
                std::memcpy(&target, v->getData().c_str(), sizeof(uint64_t));
                if(target == 0) continue;   // could be just a padding

                auto link = PerfectLinkResolver().resolveInferred(
                    target, i, module, false);
                if(link) {
                    auto lli = new LinkedLiteralInstruction();
                    lli->setLink(link);
                    lli->setData(v->getData());
                    i->setSemantic(lli);
                    delete v;
                }
            }
        }
    }
}

void LinkedInstruction::resolveLinks(Module *module,
    const std::vector<std::pair<Instruction *, address_t>>& list) {

    //TemporaryLogLevel tll("instr", 10);
    for(auto it : list) {
        auto instruction = it.first;
        auto address = it.second;
        LOG(10, "pointer at 0x" << std::hex << instruction->getAddress()
            << " pointing to 0x" << address);
        auto assembly = instruction->getSemantic()->getAssembly();
        auto linked = new LinkedInstruction(instruction);
        linked->setAssembly(assembly);

        auto link = PerfectLinkResolver().resolveInferred(
            address, instruction, module, true);

        if(link) {
            linked->setLink(link);
            auto v = instruction->getSemantic();
            instruction->setSemantic(linked);
            delete v;
            continue;
        }
        //pointer detection fails on some old gcc generated code now
        //E.g. on egalitoci, libm.so.6 uses ADR to load page address
        //assert("[LinkedInstruction] failed to create link!" && 0);
    }
}

void LinkedInstruction::saveToFile(Module *module,
    const std::vector<std::pair<Instruction *, address_t>>& list) {

    if(module->getName() == "module-(executable)") return;
    if(module->getName() == "module-(egalito)") return;
    if(module->getName() == "module-(addon)") return;

    std::string filename(CACHE_DIR "/");
    filename += module->getName() + "-inferredpointers";
    std::ofstream f(filename.c_str(), std::ios::out);
    for(auto it : list) {
        auto instruction = it.first;
        auto address = it.second;
        f << instruction->getAddress() << '\n';
        f << address << '\n';
    }

    f.close();
}

std::vector<std::pair<Instruction *, address_t>>
LinkedInstruction::loadFromFile(Module *module) {
    std::vector<std::pair<Instruction *, address_t>> list;

    if(module->getName() == "module-(executable)") return list;
    if(module->getName() == "module-(egalito)") return list;
    if(module->getName() == "module-(addon)") return list;

    std::string filename(CACHE_DIR "/");
    filename += module->getName() + "-inferredpointers";
    std::ifstream f(filename.c_str(), std::ios::in);

    char line[128];
    for(f.getline(line, 128); f.good(); f.getline(line, 128)) {
        auto addr = std::stoull(line);
        LOG(10, "instruction at 0x" << std::hex << addr);
        auto fn =
            CIter::spatial(module->getFunctionList())->findContaining(addr);
        if(!fn) {
            LOG(1, "LinkedInstruction: function not found at "
                << std::hex << addr);
        }
        auto instr = dynamic_cast<Instruction *>(
            ChunkFind().findInnermostAt(fn, addr));
        if(!instr) {
            LOG(1, "LinkedInstruction: instruction not found at "
                << std::hex << addr);
        }

        f.getline(line, 128);
        auto value = std::stoull(line);
        LOG(10, "pointer to 0x" << std::hex << value);
        list.emplace_back(instr, value);
    }
    return list;
}

void LinkedLiteralInstruction::writeTo(char *target) {
    *reinterpret_cast<uint32_t *>(target) = relocate();
}

void LinkedLiteralInstruction::writeTo(std::string &target) {
    uint32_t data = relocate();
    target.append(reinterpret_cast<const char *>(&data), getSize());
}

uint32_t LinkedLiteralInstruction::relocate() {
    return getLink()->getTargetAddress();
}

#endif
