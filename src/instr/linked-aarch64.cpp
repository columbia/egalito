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
#include "log/log.h"

#if defined(ARCH_AARCH64)
LinkedInstruction::LinkedInstruction(Instruction *source,
    const Assembly &assembly)
    : LinkDecorator<DisassembledInstruction>(assembly), source(source),
    modeInfo(&AARCH64_ImInfo[getMode(assembly)]) {
}

const LinkedInstruction::AARCH64_modeInfo_t LinkedInstruction::AARCH64_ImInfo[AARCH64_IM_MAX] = {

      /* ADRP */
      {0x9000001F,
       [] (address_t dest, address_t src) {
           diff_t disp = dest - (src & ~0xFFF);
           uint32_t imm = disp >> 12;
           return (((imm & 0x3) << 29) | ((imm & 0x1FFFFC) << 3)); },
       1},
      /* ADDIMM (in combination with ADRP) */
      {0xFFC003FF,
       [] (address_t dest, address_t src) {
           diff_t disp = dest & 0xFFF;
           uint32_t imm = disp << 10;
           return (imm & ~0xFFC003FF); },
       2
      },
      /* LDR (immediate: unsigned offset) */
      {0xFFE003FF,
       [] (address_t dest, address_t src) {
           diff_t disp = dest - src;
           uint32_t imm = (disp >> 3) << 10;
           return (imm & ~0xFFE003FF); },
       1
      },
      /* BL <label> */
      {0xFC000000,
       [] (address_t dest, address_t src) {
           diff_t disp = dest - src;
           uint32_t imm = disp >> 2;
           return (imm & ~0xFC000000); },
       0
      },
      /* B <label> (same as BL; keep it separate for debugging purpose) */
      {0xFC000000,
       [] (address_t dest, address_t src) {
           diff_t disp = dest - src;
           uint32_t imm = disp >> 2;
           return (imm & ~0xFC000000); },
       0
      },
      /* B.COND <label> */
      {0xFF00001F,
       [] (address_t dest, address_t src) {
           diff_t disp = dest - src;
           uint32_t imm = disp >> 2;
           return ((imm << 5)& ~0xFF00001F); },
       0
      },

      /* CBZ <Xt>, <label> */
      {0xFF00001F,
       [] (address_t dest, address_t src) {
           diff_t disp = dest - src;
           uint32_t imm = disp >> 2;
           return ((imm << 5)& ~0xFF00001F); },
       1
      },
      /* CBNZ <Xt>, <label> */
      {0xFF00001F,
       [] (address_t dest, address_t src) {
           diff_t disp = dest - src;
           uint32_t imm = disp >> 2;
           return ((imm << 5)& ~0xFF00001F); },
       1
      },
      /* TBZ <Xt>, #<imm>, <label> */
      {0xFFF8001F,
       [] (address_t dest, address_t src) {
           diff_t disp = dest - src;
           uint32_t imm = disp >> 2;
           return ((imm << 5)& ~0xFFF8001F); },
       2
      },
      /* TBNZ <Xt>, #<imm>, <label> */
      {0xFFF8001F,
       [] (address_t dest, address_t src) {
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
    uint32_t imm = getModeInfo()->makeImm(dest, getSource()->getAddress());
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

LinkedInstruction::Mode LinkedInstruction::getMode(
    const Assembly &assembly) {

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
    case ARM64_INS_BL:      m = AARCH64_IM_BL; break;
    case ARM64_INS_CBZ:     m = AARCH64_IM_CBZ; break;
    case ARM64_INS_CBNZ:    m = AARCH64_IM_CBNZ; break;
    case ARM64_INS_TBZ:     m = AARCH64_IM_TBZ; break;
    case ARM64_INS_TBNZ:    m = AARCH64_IM_TBNZ; break;
    case ARM64_INS_ADRP:    m = AARCH64_IM_ADRP; break;
    case ARM64_INS_ADD:     m = AARCH64_IM_ADDIMM; break;
    case ARM64_INS_LDR:     m = AARCH64_IM_LDR; break;
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
    TreeNodeConstant *offsetTree;

public:
    RegPointerPredicate(int reg) : reg(reg), offsetTree(nullptr) {}
    virtual bool cutoff(SearchState *state);
    address_t getOffset();

private:
    TreeNodeConstant *getOffsetTree(TreeNode *node);
};

TreeNodeConstant *RegPointerPredicate::getOffsetTree(TreeNode *tree) {

#if 0
    if(tree) {
        LOG(10, "reg tree is");
        IF_LOG(10) tree->print(TreePrinter(2, 0));
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
        //auto r1 = dynamic_cast<TreeNodeAddress *>(capture.get(0));
        auto r1 = dynamic_cast<TreeNodeRegister *>(capture.get(0));
        auto c2 = dynamic_cast<TreeNodeConstant *>(capture.get(1));
        if(r1 && r1->getRegister() == reg && c2) {
            return c2;
        }
    }

    return nullptr;
}

bool RegPointerPredicate::cutoff(SearchState *state) {
    LOG(10, "looking at state @ 0x" << std::hex << state->getInstruction()->getAddress());
#if 0
    Disassemble::Handle handle(true);
    LOG(10, "--------REG ");
    const auto &regs = state->getRegs();
    for(size_t r = 0; r < regs.size(); r ++) {
        auto tree = state->getRegTree(r);
        if(!tree) continue;

        LOG0(10, "        REG " << cs_reg_name(handle.raw(), r) << ": ");
        IF_LOG(10) tree->print(TreePrinter(3, 1));
        LOG(10, "");
    }
    for(auto const &tree : state->getMemTree()) {
        LOG(10, "--------MEM ");
        IF_LOG(10) tree.first->print(TreePrinter(3,1));
        LOG0(10, ": ");
        IF_LOG(10) tree.second->print(TreePrinter(3, 1));
        LOG(10, "");
    }
#endif

    auto tree = getOffsetTree(state->getRegTree(reg));
    if(tree) {
        offsetTree = tree;
#if 0
        LOG(10, "found offsetTree: ");
        IF_LOG(10) tree->print(TreePrinter(2, 0));
#endif
    }
    else {
        auto v = dynamic_cast<DisassembledInstruction *>(
            state->getInstruction()->getSemantic());
        if(v) {
            auto assembly = v->getAssembly();
            if(assembly->getId() == ARM64_INS_ADD
               || assembly->getId() == ARM64_INS_LDR
               || assembly->getId() == ARM64_INS_LDRB
               || assembly->getId() == ARM64_INS_LDRH
               || assembly->getId() == ARM64_INS_LDRSB
               || assembly->getId() == ARM64_INS_LDRSH
               || assembly->getId() == ARM64_INS_LDRSW
               ) {

                auto r = assembly->getAsmOperands()->getOperands()[0].reg;
                auto tree = getOffsetTree(state->getRegTree(r));
                if(tree) {
                    offsetTree = tree;
                }
            }
            else if(assembly->getId() == ARM64_INS_STR
                    || assembly->getId() == ARM64_INS_STRB
                    || assembly->getId() == ARM64_INS_STRH
                    ) {
                for(auto mem : state->getMemTree()) {
#if 0
                    LOG(10, "memtree: ");
                    IF_LOG(10) {
                        mem.first->print(TreePrinter(2, 0));
                        LOG(10, "");
                        mem.second->print(TreePrinter(2, 0));
                    }
                    LOG(10, "");
#endif
                    auto tree = getOffsetTree(mem.first);
                    if(tree) {
                        offsetTree = tree;
                        break;
                    }
                }
            }
        }
    }

    return (offsetTree != nullptr);
}

address_t RegPointerPredicate::getOffset() {
#if 0
    LOG(10, "tree is: ");
    if(offsetTree) {
        IF_LOG(10) offsetTree->print(TreePrinter(2, 0));
    }
    else {
        LOG(10, "--------not found------------");
    }
    LOG(10, "");
#endif
    return (offsetTree) ? offsetTree->getValue() : 0;
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

address_t LinkedInstruction::makeTargetAddress(Instruction *instruction,
    Assembly *assembly, int regIndex) {

    Function *function = dynamic_cast<Function *>(
        instruction->getParent()->getParent());

    auto reg =
        assembly->getAsmOperands()->getOperands()[regIndex].reg;

    auto factory = CFGFactory::instance();
    auto cfg = factory.getControlFlowGraph(function);

    RegPointerPredicate rpp(reg);
    ForwardSlicingSearch search(cfg, &rpp);
    auto next = dynamic_cast<Instruction *>(instruction->getNextSibling());

    LOG(10, "makeTargetAddress for 0x" << std::hex << instruction->getAddress());
    search.sliceAt(next, reg);

#if 0
    if(rpp.getOffset() == 0) {
        cfg->dump();
        LOG(10, "function name = " << function->getName());
        LOG(10, "function size = " << std::dec << function->getSize());
    }
#endif

    return assembly->getAsmOperands()->getOperands()[1].imm + rpp.getOffset();
}

LinkedInstruction *LinkedInstruction::makeLinked(Module *module,
    Instruction *instruction, Assembly *assembly) {

    if(assembly->getId() == ARM64_INS_ADRP) {
        address_t target = LinkedInstruction::makeTargetAddress(
            instruction, assembly, 0);
        //LOG(1, "target: 0x" << std::hex << target);
        auto found = CIter::spatial(module->getFunctionList())->find(target);
        if(found) {
            //LOG(1, " ==> " << found->getName());
            auto link = new ExternalNormalLink(found);
            auto linked = new LinkedInstruction(instruction, *assembly);
            linked->setLink(link);
            return linked;
        }
        else {
            //LOG(1, " --> data link");
            auto link = LinkFactory::makeDataLink(module, target, true);
            if(!link) throw "failed to create link!";
            auto linked = new LinkedInstruction(instruction, *assembly);
            linked->setLink(link);
            return linked;
        }
    }
    return nullptr;
}
#endif
