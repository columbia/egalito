#include <algorithm>
#include <string>
#include "stackextend.h"
#include "chunk/chunk.h"
#include "chunk/concrete.h"
#include "chunk/instruction.h"
#include "chunk/mutator.h"
#include "chunk/register.h"
#include "disasm/disassemble.h"
#include "log/log.h"
#include "chunk/dump.h"

#ifdef ARCH_AARCH64
void StackExtendPass::visit(Module *module) {
    if(extendSize >= 4096) {
        LOG(1, "can't extend over 4096");
    }
    else {
        LOG(1, "extending by " << extendSize);
        recurse(module);
    }
}

void StackExtendPass::visit(Function *function) {
    if(!shouldApply(function)) return;

    FrameType frame(function);
    frame.dump();

    extendStack(function, &frame);
    shrinkStack(function, &frame);
    ChunkMutator(function).updatePositions();
    useStack(function, &frame);

#if 1
    LOG(1, "modified:");
    ChunkDumper dumper;
    function->accept(&dumper);
#endif
}

bool StackExtendPass::shouldApply(Function *function) {
    for(auto b : function->getChildren()->getIterable()->iterable()) {
        for(auto i : b->getChildren()->getIterable()->iterable()) {
            if(auto cs = i->getSemantic()->getCapstone()) {
                cs_arm64 *x = &cs->detail->arm64;
                if(x->op_count >= 1
                   && x->operands[0].type == ARM64_OP_REG
                   && (x->operands[0].reg == ARM64_REG_X18
                       || x->operands[0].reg == ARM64_REG_W18)) {

                    LOG(1, "x18 is modified in " << function->getName()
                        << " at " << i->getName());

                    LOG(1, "original:");
                    ChunkDumper dumper;
                    function->accept(&dumper);
                    return true;
                }
            }
        }
    }

    return false;
}

void StackExtendPass::extendStack(Function *function, FrameType *frame) {

    auto firstB = function->getChildren()->getIterable()->get(0);
    auto bin_sub = AARCH64InstructionBinary(
        0xD1000000 | extendSize << 10 | 31 << 5 | 31);
    auto instr_sub = Disassemble::instruction(bin_sub.getVector());
    ChunkMutator(firstB).prepend(instr_sub);

    auto bin_add = AARCH64InstructionBinary(
        0x91000000 | extendSize << 10 | 29 << 5 | 29);
    auto instr_add = Disassemble::instruction(bin_add.getVector());
    if(auto ins = frame->getSetBPInstr()) {
        auto block = dynamic_cast<Block *>(ins->getParent());
        ChunkMutator(block).insertAfter(ins, instr_add);
    }
}

void StackExtendPass::shrinkStack(Function *function, FrameType *frame) {
    for(auto ins : frame->getResetSPInstrs()) {
        auto bin_sub = AARCH64InstructionBinary(
            0xD1000000 | extendSize << 10 | 29 << 5 | 29);
        auto block = dynamic_cast<Block *>(ins->getParent());
        auto instr_sub = Disassemble::instruction(bin_sub.getVector());
        ChunkMutator(block).insertBefore(ins, instr_sub);
    }

    std::map<Instruction *, Instruction *>prevs;
    for(auto ins : frame->getReturnInstrs()) {
        auto bin_add = AARCH64InstructionBinary(
            0x91000000 | extendSize << 10 | 31 << 5 | 31);
        auto block = dynamic_cast<Block *>(ins->getParent());
        auto instr_add = Disassemble::instruction(bin_add.getVector());
        ChunkMutator(block).insertBefore(ins, instr_add);
        prevs[ins] = instr_add;
    }

    for(auto b : function->getChildren()->getIterable()->iterable()) {
        for(auto i : b->getChildren()->getIterable()->iterable()) {
            if(auto cfi = dynamic_cast<ControlFlowInstruction *>(
                i->getSemantic())) {

                auto link = cfi->getLink();
                for(auto ins : frame->getReturnInstrs()) {
                    if(link->getTarget() == ins) {
                        cfi->setLink(new NormalLink(prevs[ins]));
                        delete link;
                        break;
                    }
                }
            }
        }
    }
}

FrameType::FrameType(Function *function)
    : baseSize(0), outArgSize(0), setBPInstr(nullptr) {
    baseSize = getFrameSize(function);

    if(baseSize > 0) {
        auto firstB = function->getChildren()->getIterable()->get(0);
        for(auto i : firstB->getChildren()->getIterable()->iterable()) {
            if(auto cs = i->getSemantic()->getCapstone()) {
                cs_arm64 *x = &cs->detail->arm64;
                if(x->operands[0].type == ARM64_OP_REG
                   && x->operands[0].reg == ARM64_REG_X29
                   && x->operands[1].type == ARM64_OP_REG
                   && x->operands[1].reg == ARM64_REG_SP) {

                    if(cs->id == ARM64_INS_MOV) {
                        outArgSize = 0;
                        setBPInstr = i;
                    }
                    else if(cs->id == ARM64_INS_ADD) {
                        outArgSize = x->operands[2].imm;
                        setBPInstr = i;
                    }
                    break;
                }
            }
        }
    }

    for(auto b : function->getChildren()->getIterable()->iterable()) {
        for(auto i : b->getChildren()->getIterable()->iterable()) {
            if(dynamic_cast<ReturnInstruction *>(i->getSemantic())) {
                returnInstrs.push_back(i);
            }
            else if(auto cfi = dynamic_cast<ControlFlowInstruction *>(
                i->getSemantic())) {

                if(cfi->getMnemonic() == std::string("b")
                   || cfi->getMnemonic().find("b.", 0) != std::string::npos) {

                    auto link = dynamic_cast<NormalLink *>(cfi->getLink());
                    if(link && dynamic_cast<Function *>(&*link->getTarget())) {
                        returnInstrs.push_back(i);
                    }
                }
            }
        }
    }

    for(auto const &retInstr : returnInstrs) {
        auto parent = dynamic_cast<Block *>(retInstr->getParent());
        for(auto i : parent->getChildren()->getIterable()->iterable()) {
            if(auto cs = i->getSemantic()->getCapstone()) {
                cs_arm64 *x = &cs->detail->arm64;
                if(cs->id == ARM64_INS_MOV
                   && x->operands[0].reg == ARM64_REG_SP
                   && x->operands[1].type == ARM64_OP_REG
                   && x->operands[1].reg == ARM64_REG_X29) {

                    resetSPInstrs.push_back(i);
                }
            }
        }
    }
}

size_t FrameType::getFrameSize(Function *function) {
    auto firstB = function->getChildren()->getIterable()->get(0);
    for(auto i : firstB->getChildren()->getIterable()->iterable()) {
        if(auto cs = i->getSemantic()->getCapstone()) {
            cs_arm64 *x = &cs->detail->arm64;
            if(cs->id == ARM64_INS_SUB
               && x->operands[0].reg == ARM64_REG_SP) {
                return x->operands[2].imm;  // doesn't handle shift and ext
            }
            else if(cs->id == ARM64_INS_STP
                    && x->operands[2].type == ARM64_OP_MEM
                    && x->writeback) {
                return -(x->operands[2].mem.disp);
            }
        }
    }
    return 0;
}

void FrameType::dump() {
    CLOG(1, "frame size = 0x%x", baseSize);
    CLOG(1, "out-going arg size = %d", outArgSize);
    LOG(1, "BP set @ " << (setBPInstr ? setBPInstr->getName() : ""));
}

static Register getGPRegisterName(int reg) {
    static const Register promotion[][2] = {
        {ARM64_REG_W16, ARM64_REG_X16},
        {ARM64_REG_W17, ARM64_REG_X17},
        {ARM64_REG_W18, ARM64_REG_X18},
        {ARM64_REG_W19, ARM64_REG_X19},
        {ARM64_REG_W20, ARM64_REG_X20},
        {ARM64_REG_W21, ARM64_REG_X21},
        {ARM64_REG_W22, ARM64_REG_X22},
        {ARM64_REG_W23, ARM64_REG_X23},
        {ARM64_REG_W24, ARM64_REG_X24},
        {ARM64_REG_W25, ARM64_REG_X25},
        {ARM64_REG_W26, ARM64_REG_X26},
        {ARM64_REG_W27, ARM64_REG_X27},
        {ARM64_REG_W28, ARM64_REG_X28},
    };

    for(size_t i = 0; i < sizeof(promotion)/sizeof(*promotion); i ++) {
        if(promotion[i][0] == reg) {
            return promotion[i][1];
        }
        else if(promotion[i][1] == reg) {
            return promotion[i][1];
        }
    }

    return INVALID_REGISTER;
}


RegisterUsage::RegisterUsage(Function *function, Register x)
    : function(function), regX(x), cfg(ControlFlowGraph(function)),
      categorized(false) {

    for(auto b : function->getChildren()->getIterable()->iterable()) {
        std::vector<Instruction *> instructionList;
        for(auto ins : b->getChildren()->getIterable()->iterable()) {
            if(auto cs = ins->getSemantic()->getCapstone()) {
                cs_arm64 *x = &cs->detail->arm64;
                for(int i = 0; i < x->op_count; ++i) {
                    if(x->operands[i].type == ARM64_OP_REG
                       && (x->operands[i].reg == ARM64_REG_X18
                           || x->operands[i].reg == ARM64_REG_W18)) {

                        instructionList.push_back(ins);
                        break;
                    }
                }
            }
        }
        if(instructionList.size() > 0) {
            UsageList[b] = instructionList;
        }
    }
}

void RegisterUsage::categorizeBlocks() {
    if(categorized) return;
    categorized = true;

    cfg.dump();

    for(auto u : UsageList) {
        auto block = u.first;
        auto node = cfg.get(block);
        bool isLeaf = true;
        for(auto link : node->forwardLinks()) {
            auto nextNode = cfg.get(link.getID());
            if(nextNode != node
               && UsageList.find(nextNode->getBlock()) != UsageList.end()) {
                isLeaf = false;
                break;
            }
        }
        if(isLeaf) {
            leafBlockList.insert(block);
        }

        bool isRoot = true;
        for(auto link : node->backwardLinks()) {
            auto prevNode = cfg.get(link.getID());
            if(prevNode != node
               && UsageList.find(prevNode->getBlock()) != UsageList.end()) {
                isRoot = false;
                break;
            }
        }
        if(isRoot) {
            rootBlockList.insert(block);
        }
    }

    std::set_intersection(rootBlockList.begin(), rootBlockList.end(),
                          leafBlockList.begin(), leafBlockList.end(),
                          std::inserter(singleBlockList, singleBlockList.end()));

    for(auto b : singleBlockList) {
        rootBlockList.erase(b);
        leafBlockList.erase(b);
    }
}

Register RegisterUsage::getDualRegister(Block *block) {
    static const Register candidates[] = {
        ARM64_REG_X16, ARM64_REG_X17, ARM64_REG_X18, ARM64_REG_X19,
        ARM64_REG_X20, ARM64_REG_X21, ARM64_REG_X22, ARM64_REG_X23,
        ARM64_REG_X24, ARM64_REG_X25, ARM64_REG_X26, ARM64_REG_X27,
        ARM64_REG_X28
    };
    Register dualReg = INVALID_REGISTER;
    std::set<Register> unusable;
    std::map<Register,int> use_count;
    for(auto reg : candidates) {
        use_count[reg] = 0;
    }

    Instruction *begin(nullptr), *end(nullptr);
    bool inRegion;
    if(singleBlockList.find(block) == singleBlockList.end()) {
        inRegion = true;
    }
    else {
        inRegion = false;
        begin = UsageList[block].front();
        end = UsageList[block].back();
    }

    for (auto ins : block->getChildren()->getIterable()->iterable()) {
        if(!inRegion) {
            if(ins == begin) {
                inRegion = true;
            }
        }
        if(!inRegion) continue;

        if(ins == end) {
            //inRegion = false;
            break;
        }

        if (auto cs = ins->getSemantic()->getCapstone()) {
            cs_arm64 *x = &cs->detail->arm64;
            for(int i = 0; i < x->op_count; ++i) {
                std::vector<Register> regOperands;
                bool withX = false;
                if(x->operands[i].type == ARM64_OP_REG) {
                    Register reg = getGPRegisterName(x->operands[i].reg);
                    if(reg == INVALID_REGISTER) continue;

                    if(reg == regX) {
                        withX = true;
                    }
                    LOG(1, "reg: " << (reg - ARM64_REG_X0));
                    regOperands.push_back(reg);
                }

                if(withX) {
                    for(auto r : regOperands) {
                        unusable.insert(r);
                    }
                }
                else {
                    for(auto r : regOperands) {
                        use_count[r] += 1;
                    }
                }
            }
        }
    }


    typedef std::pair<Register, int> regUse;
    std::vector<regUse> sorted(use_count.begin(), use_count.end());
    std::sort(sorted.begin(), sorted.end(),
              [] (regUse x, regUse y) { return x.second < y.second; });

    LOG(1, "register usage:");
    for(auto reg : sorted) {
        LOG0(1, "X" << (reg.first - ARM64_REG_X0));
        if(unusable.find(reg.first) != unusable.end()) {
            LOG(1, ": unusable");
        }
        else {
            LOG(1, ": " << reg.second);
        }
    }

    for(auto reg : sorted) {
        if(unusable.find(reg.first) != unusable.end()) {
            continue;
        }
        dualReg = reg.first;
        LOG(1, "use ARM64_REG_X" << (dualReg - ARM64_REG_X0));
        break;
    }

    return dualReg;
}
#endif

