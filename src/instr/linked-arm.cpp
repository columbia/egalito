#include <cstring>  // for memcpy
#include "linked-arm.h"
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

#if defined(ARCH_ARM)
LinkedInstruction::LinkedInstruction(Instruction *source,
    const Assembly &assembly)
    : LinkDecorator<DisassembledInstruction>(assembly), source(source),
    modeInfo(&ARM_ImInfo[getMode(assembly)]) {
}

const LinkedInstruction::ARM_modeInfo_t LinkedInstruction::ARM_ImInfo[ARM_IM_MAX] = {

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
    LOG(1, "mode: " << getModeInfo() - ARM_ImInfo);
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
    if(operands[modeInfo->immediateIndex].type == ARM_OP_IMM) {
        return operands[modeInfo->immediateIndex].imm;
    }
    else {  // mem for LDR x0, [x0,#4048]
        return operands[modeInfo->immediateIndex].mem.disp;
    }
}

void LinkedInstruction::writeTo(char *target) {
    *reinterpret_cast<uint32_t *>(target) = rebuild();
}
void LinkedInstruction::writeTo(std::string &target) {
    uint32_t data = rebuild();
    target.append(reinterpret_cast<const char *>(&data), getSize());
}
std::string LinkedInstruction::getData() {
    std::string data;
    writeTo(data);
    return data;
}

LinkedInstruction::Mode LinkedInstruction::getMode(
    const Assembly &assembly) {

  // TODO: This is not complete yet.
    LinkedInstruction::Mode m;
    switch(assembly.getId()) {
    case ARM_INS_B:
        if(assembly.getBytes()[3] == 0x54) {
            m = ARM_IM_BCOND;
        }
        else {
            m = ARM_IM_B;
        }
        break;
    case ARM_INS_BL:      m = ARM_IM_BL; break;
    case ARM_INS_BLX:     m = ARM_IM_BLX; break;
    case ARM_INS_BX:      m = ARM_IM_BX; break;
    case ARM_INS_BXJ:     m = ARM_IM_BXJ; break;
    case ARM_INS_CBZ:     m = ARM_IM_CBZ; break;
    case ARM_INS_CBNZ:    m = ARM_IM_CBNZ; break;
    case ARM_INS_ADD:     m = ARM_IM_ADDIMM; break;
    case ARM_INS_LDR:     m = ARM_IM_LDR; break;
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
        auto c2 = dynamic_cast<TreeNodeConstant *>(capture.get(1));
        if(r1 && r1->getRegister() == reg && c2) {
            return c2;
        }
    }

    return nullptr;
}

bool RegPointerPredicate::cutoff(SearchState *state) {
    auto tree = getOffsetTree(state->getRegTree(reg));
    if(tree) {
        offsetTree = tree;
    }
    else {
        auto v = dynamic_cast<DisassembledInstruction *>(
            state->getInstruction()->getSemantic());
        if(v) {
            auto assembly = v->getAssembly();
            if(assembly->getId() == ARM_INS_ADD
               || assembly->getId() == ARM_INS_LDR
               || assembly->getId() == ARM_INS_LDRB
               || assembly->getId() == ARM_INS_LDRH
               || assembly->getId() == ARM_INS_LDRSB
               || assembly->getId() == ARM_INS_LDRSH
               ) {

                auto r = assembly->getAsmOperands()->getOperands()[0].reg;
                auto tree = getOffsetTree(state->getRegTree(r));
                if(tree) {
                    offsetTree = tree;
                }
            }
            else if(assembly->getId() == ARM_INS_STR
                    || assembly->getId() == ARM_INS_STRB
                    || assembly->getId() == ARM_INS_STRH
                    ) {
                for(auto mem : state->getMemTree()) {
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
    LOG(1, "tree is: ");
    if(offsetTree) {
        IF_LOG(1) offsetTree->print(TreePrinter(2, 0));
    }
    else {
        LOG(1, "--------not found------------");
    }
    LOG(1, "");
#endif
    return (offsetTree) ? offsetTree->getValue() : 0;
}

address_t LinkedInstruction::makeTargetAddress(Instruction *instruction,
                                               Assembly *assembly, int regIndex) {

  Function *function = dynamic_cast<Function *>(
                                                instruction->getParent()->getParent());

  auto reg =
    assembly->getAsmOperands()->getOperands()[regIndex].reg;

  ControlFlowGraph cfg(function);

  RegPointerPredicate rpp(reg);
  ForwardSlicing forward;
  SlicingSearch search(&cfg, &forward, &rpp);
  auto next = dynamic_cast<Instruction *>(instruction->getNextSibling());
  search.sliceAt(next, reg);

  return assembly->getAsmOperands()->getOperands()[1].imm + rpp.getOffset();

}

LinkedInstruction *LinkedInstruction::makeLinked(Module *module,
    Instruction *instruction, Assembly *assembly) {

    if(assembly->getId() == ARM_INS_BL) {
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
            // //LOG(1, " --> data link");
            // auto link = new DataOffsetLink(
            //     module->getElfSpace()->getElfMap(), target);
            // auto linked = new LinkedInstruction(instruction, *assembly);
            // linked->setLink(link);
            // return linked;
        }
    }
    return nullptr;
}
#endif
