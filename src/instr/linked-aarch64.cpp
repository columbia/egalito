#include <cstring>  // for memcpy
#include "linked-aarch64.h"
#include "instr.h"
#include "analysis/slicingtree.h"
#include "analysis/controlflow.h"
#include "analysis/slicing.h"
#include "analysis/slicingmatch.h"
#include "chunk/link.h"
#include "disasm/disassemble.h"
#include "elf/elfspace.h"
#include "util/streamasstring.h"

#include <cstdio>  // for std::fflush
#include "log/log.h"
#include "chunk/dump.h"
#include "log/registry.h"

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
    case ARM64_INS_ADD:     m = AARCH64_IM_ADDIMM;  break;
    case ARM64_INS_LDR:     m = AARCH64_IM_LDR;     break;
    case ARM64_INS_LDRH:    m = AARCH64_IM_LDRH;    break;
    case ARM64_INS_LDRB:    m = AARCH64_IM_LDRB;    break;
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


class RegPointerPredicate : public SlicingHalt {
private:
    int reg;
    unsigned long offset;
    std::vector<Instruction *> offsetInstructionList;

public:
    RegPointerPredicate(int reg) : reg(reg), offset(0) {}
    virtual bool cutoff(SearchState *state);
    unsigned long getOffset() const { return offset; }
    std::vector<Instruction *> getOffsetInstructionList() const
        { return offsetInstructionList; }

private:
    TreeNodeConstant *getOffsetTree(TreeNode *node, SearchState *state);
};

TreeNodeConstant *RegPointerPredicate::getOffsetTree(TreeNode *tree,
    SearchState *state) {

#if 0
    if(tree) {
        LOG(10, "reg tree is");
        IF_LOG(10) tree->print(TreePrinter(2, 0));
        LOG(10, "");
    }
#endif

    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternAny>,
        TreePatternCapture<TreePatternAny>
    > TreePatternOffset;

    typedef TreePatternUnary<TreeNodeDereference,
        TreePatternCapture<TreePatternOffset>
    > TreePatternOffset2;

    TreeCapture capture;
    if(TreePatternOffset2::matches(tree, capture)) {
        tree = capture.get(0);
    }

    capture.clear();
    if(TreePatternOffset::matches(tree, capture)) {
        auto r1 = dynamic_cast<TreeNodeRegister *>(capture.get(0));
        if(!r1) {
            for(auto m : state->getMemTrees()) {
                if(m.first->canbe(capture.get(0))) {
                    r1 = dynamic_cast<TreeNodeRegister *>(m.second);
                    if(r1) break;
                }
            }
        }
        auto c2 = dynamic_cast<TreeNodeConstant *>(capture.get(1));
        if(r1 && r1->getRegister() == reg && c2) {
            return c2;
        }
    }

    return nullptr;
}

bool RegPointerPredicate::cutoff(SearchState *state) {
    TreeNodeConstant *offsetTree = nullptr;
    //LOG(1, "looking at state @ 0x" << std::hex << state->getInstruction()->getAddress());

    auto v = dynamic_cast<DisassembledInstruction *>(
        state->getInstruction()->getSemantic());
    if(v) {
        auto assembly = v->getAssembly();
        if(assembly->getId() == ARM64_INS_ADD) {
            auto r = assembly->getAsmOperands()->getOperands()[0].reg;
            if(state->getReg(r)) {
                auto tree = getOffsetTree(state->getRegTree(r), state);
                if(tree) {
                    offsetTree = tree;
                }
            }
        } else if(1
            || assembly->getId() == ARM64_INS_LDR
            || assembly->getId() == ARM64_INS_LDRB
            || assembly->getId() == ARM64_INS_LDRH
            || assembly->getId() == ARM64_INS_LDRSB
            || assembly->getId() == ARM64_INS_LDRSH
            || assembly->getId() == ARM64_INS_LDRSW
            || assembly->getId() == ARM64_INS_STR
            || assembly->getId() == ARM64_INS_STRB
            || assembly->getId() == ARM64_INS_STRH
            ) {
            if(auto m = state->getMemTree()) {
                if(auto tree = getOffsetTree(m, state)) {
                    offsetTree = tree;
                }
            }
            else {
                LOG(10, "skipping because base is not interesting");
            }
        }
    }

    if(offsetTree) {
        if(offsetInstructionList.size() == 0) {
            offset = offsetTree->getValue();
        }

        if(offset == offsetTree->getValue()) {
            LOG(10, "the offset is given at "
                << state->getInstruction()->getAddress());
            offsetInstructionList.push_back(state->getInstruction());
        }
    }

    /* don't cutoff early: there could be more than one offset instructions */
    return false;
}

class CFGFactory {
private:
    Function *lastFunction;
    ControlFlowGraph *cfg;

public:
    CFGFactory() : lastFunction(nullptr), cfg(nullptr) {}
    ~CFGFactory() { delete cfg; }
    ControlFlowGraph *getControlFlowGraph(Function *function);

    static CFGFactory& instance() {
        static CFGFactory factory;
        return factory;
    }
};

ControlFlowGraph *CFGFactory::getControlFlowGraph(Function *function) {
    if(lastFunction != function) {
        delete cfg;
        lastFunction = function;
        cfg = new ControlFlowGraph(function);
    }
    return cfg;
}

Instruction *LinkedInstruction::getNextInstruction(Instruction *instruction) {
    Instruction *next = nullptr;
    next = static_cast<Instruction *>(instruction->getNextSibling());
    if(!next) {
        auto nextb = dynamic_cast<Block *>(
            instruction->getParent()->getNextSibling());
        next = nextb->getChildren()->getIterable()->get(0);
    }
    return next;
}

LinkedInstruction *LinkedInstruction::makeLinked(Module *module,
    Instruction *instruction, Assembly *assembly) {

    if(assembly->getId() == ARM64_INS_ADRP) {
        Function *function = dynamic_cast<Function *>(
            instruction->getParent()->getParent());

        auto reg = assembly->getAsmOperands()->getOperands()[0].reg;

        auto factory = CFGFactory::instance();
        auto cfg = factory.getControlFlowGraph(function);

        RegPointerPredicate rpp(reg);
        ForwardSlicingSearch search(cfg, &rpp);
        auto next = getNextInstruction(instruction);

        LOG(10, "makeLinked for 0x" << std::hex << instruction->getAddress());
        LOG(10, "    searching from 0x" << std::hex << next->getAddress());
        search.sliceAt(next, reg);

        address_t target = assembly->getAsmOperands()->getOperands()[1].imm
            + rpp.getOffset();
        if(rpp.getOffsetInstructionList().size() == 0) {
#if 0
            GroupRegistry::getInstance()->applySetting("analysis", 20);
            GroupRegistry::getInstance()->applySetting("instr", 20);
            LOG(1, "function name = " << function->getName());
            LOG(1, "function size = " << std::dec << function->getSize());

            ChunkDumper dump;
            function->accept(&dump);

            cfg->dump();
            std::cout.flush();
            std::fflush(stdout);

            // redo to get log
            search.sliceAt(next, reg);
#endif
            LOG(1, "Couldn't find the offset instruction for"
                << function->getName());
            throw "failed";
            //return nullptr;
        }

        LOG(10, "target: 0x" << std::hex << target);
        auto found = CIter::spatial(module->getFunctionList())->find(target);
        auto linked = new LinkedInstruction(instruction, *assembly);
        Link *link = nullptr, *link2 = nullptr;
        if(found) {
            LOG(10, " ==> " << found->getName());
            link = new ExternalNormalLink(found);
            link2 = new ExternalNormalLink(found);
        }
        else {
            LOG(10, " --> data link");
            link = LinkFactory::makeDataLink(module, target, true);
            if(!link) throw "failed to create link!";
            link2 = LinkFactory::makeDataLink(module, target, true);
        }
        linked->setLink(link);

        // set link to the offset instruction
        // !!! Is it really ok to share link2?
        for(auto offsetInst : rpp.getOffsetInstructionList()) {
            auto semantic2 = offsetInst->getSemantic();
            auto assembly2 = semantic2->getAssembly();
            auto linked2 = new LinkedInstruction(offsetInst, *assembly2);
            linked2->setLink(link2);
            offsetInst->setSemantic(linked2);
            delete semantic2;
        }

        return linked;
    }
    return nullptr;
}
#endif
