#include <algorithm>
#include <string>
#include <assert.h>
#include "stackextend.h"
#include "analysis/jumptable.h"
#include "analysis/usedefutil.h"
#include "analysis/controlflow.h"
#include "analysis/usedef.h"
#include "analysis/walker.h"
#include "chunk/chunk.h"
#include "chunk/concrete.h"
#include "chunk/dump.h"
#include "disasm/makesemantic.h"
#include "instr/concrete.h"
#include "disasm/disassemble.h"
#include "operation/mutator.h"
#include "log/log.h"
#include "log/temp.h"

void StackExtendPass::visit(Module *module) {
#ifdef ARCH_X86_64
    if(0) {}
#elif defined(ARCH_AARCH64)
    if(extendSize >= 504) { // due to stp limitation
        LOG(1, "can't extend over 504");
    }
    else if(extendSize & 0x7) {
        LOG(1, "extend size must be multiple of 8");
    }
#endif
    else {
        LOG(5, "extending by " << extendSize);
        recurse(module);
    }
}

void StackExtendPass::visit(Function *function) {
    if(!shouldApply(function)) return;

    FrameType frame(function);
    IF_LOG(10) frame.dump();

    if(extendSize > 0) {
#ifdef ARCH_X86_64
        extendStack(function, &frame);
#else
        addExtendStack(function, &frame);
        addShrinkStack(function, &frame);
#endif
        ChunkMutator(function).updatePositions();
    }
    useStack(function, &frame);
    IF_LOG(10) frame.dump();
}

#ifdef ARCH_X86_64
static size_t getLoadStackOffset(UDState *state) {
    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternRegisterIs<X86_REG_RSP>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > StackAccessForm1;

    typedef TreePatternBinary<TreeNodeSubtraction,
        TreePatternRegisterIs<X86_REG_RSP>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > StackAccessForm2;

    typedef TreePatternUnary<TreeNodeDereference,
        StackAccessForm1
    > StackDerefForm1;

    typedef TreePatternUnary<TreeNodeDereference,
        StackAccessForm2
    > StackDerefForm2;

    for(auto& def : state->getRegDefList()) {
        TreeCapture cap1, cap2;
        if(StackDerefForm1::matches(def.second, cap1)) {
            auto c = dynamic_cast<TreeNodeConstant *>(cap1.get(0));
            return c->getValue();
        }
        if(StackDerefForm2::matches(def.second, cap2)) {
            auto c = dynamic_cast<TreeNodeConstant *>(cap2.get(0));
            return c->getValue();
        }

        if(StackAccessForm1::matches(def.second, cap1)) { // add $0x10,%rsp
            return 0;
        }
        if(StackAccessForm2::matches(def.second, cap2)) { // sub $0x10,%rsp
            return 0;
        }
    }
    for(auto& def : state->getMemDefList()) {
        TreeCapture cap1, cap2;
        if(StackAccessForm1::matches(def.second, cap1)) {
            auto c = dynamic_cast<TreeNodeConstant *>(cap1.get(0));
            return c->getValue();
        }
        if(StackAccessForm2::matches(def.second, cap2)) {
            auto c = dynamic_cast<TreeNodeConstant *>(cap2.get(0));
            return c->getValue();
        }
    }
    state->dumpState();
    throw "getLoadStackOffset: error";
    //return 0;
}

static size_t getCurrentFrameSize(UDState *state) {
    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternRegisterIs<X86_REG_RSP>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > StackAccessForm1;

    typedef TreePatternBinary<TreeNodeSubtraction,
        TreePatternRegisterIs<X86_REG_RSP>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > StackAccessForm2;

    size_t size = 0;
    bool searching = true;
    auto f = [&](UDState *s, TreeCapture cap) {
        LOG(11, "state = " << s->getInstruction()->getAddress());
        LOG0(11, "cap: ");
        IF_LOG(11) cap.get(0)->print(TreePrinter(2, 0));
        LOG(11, "");
        auto c = dynamic_cast<TreeNodeConstant *>(cap.get(0));
        size += c->getValue();
        state = s;
        searching = true;
        return true;
    };
    do {
        searching = false;
        FlowUtil::searchUpDef<StackAccessForm1>(state, X86_REG_RSP, f);
        if(!searching) {
            FlowUtil::searchUpDef<StackAccessForm2>(state, X86_REG_RSP, f);
        }
    } while (searching);
    return size;
}
#endif

void StackExtendPass::adjustOffset(Instruction *instruction) {
#ifdef ARCH_X86_64
    LOG(1, "adjusting displacement in " << instruction->getAddress());
    //ChunkDumper dumper;
    //instruction->accept(&dump);

    auto v
        = dynamic_cast<DisassembledInstruction *>(instruction->getSemantic());
    assert(!!v);
    auto sfi = new StackFrameInstruction(v->getAssembly());
    sfi->addToDisplacementValue(extendSize);
    instruction->setSemantic(sfi);
    //instruction->accept(&dump);
    delete v;
#endif
}

void StackExtendPass::extendStack(Function *function, FrameType *frame) {
#ifdef ARCH_X86_64
    ControlFlowGraph cfg(function);
    UDConfiguration config(&cfg);
    UDRegMemWorkingSet working(function, &cfg);
    UseDef usedef(&config, &working);

    IF_LOG(10) cfg.dump();
    IF_LOG(10) cfg.dumpDot();

    SccOrder order(&cfg);
    order.genFull(0);
    //TemporaryLogLevel tll("analysis", 11);
    //TemporaryLogLevel tll2("pass", 10);
    usedef.analyze(order.get());

    for(auto block : CIter::children(function)) {
        for(auto instr : CIter::children(block)) {
            auto state = working.getState(instr);
            for(auto& ref : state->getRegRefList()) {
                auto reg = ref.first;
                if(reg == X86_REG_RSP) {
                    LOG(10, std::hex << instr->getAddress() << " refs rsp");
                    if(auto offset = getLoadStackOffset(state)) {
                        auto frameSize = getCurrentFrameSize(state);
                        LOG(10, "offset = " << offset
                            << " frame size = " << frameSize);
                        if(frameSize <= offset) {
                            adjustOffset(instr);
                        }
                    }
                }
            }
        }
    }

    // prologue -- sub $0x8,%rsp
    auto firstB = function->getChildren()->getIterable()->get(0);
    if(!saveList.empty()) {
        for(auto r : saveList) {
            std::vector<unsigned char> pushBin;
            if(r >= 8) {
                pushBin.push_back(0x41);
                pushBin.push_back(0x50 + r - 8);
            }
            else {
                pushBin.push_back(0x50 + r);
            }
            auto pushIns = Disassemble::instruction(pushBin);
            ChunkMutator(firstB).prepend(pushIns);
        }
    }
    else {
        std::vector<unsigned char> bin_sub = {0x48, 0x83, 0xec};
        for(int s = sizeof(int) * 4 - 8; s >= 0; s -= 8) {
            unsigned char c = (extendSize >> s) & 0xff;
            if(c) bin_sub.push_back(c);
        }
        ChunkMutator(firstB).prepend(Disassemble::instruction(bin_sub));
    }

    // epilogue -- add $0x8,%rsp
    if(!saveList.empty()) {
        for(auto ins : frame->getEpilogueInstrs()) {
            // Note: we use insertBeforeJumpTo, so we have to keep changing the
            // insertion point to be equivalent to insertBefore(ins, .)
            auto insPoint = ins;
            for(auto r : saveList) {
                std::vector<unsigned char> popBin;
                if(r >= 8) {
                    popBin.push_back(0x41);
                    popBin.push_back(0x58 + r - 8);
                }
                else {
                    popBin.push_back(0x58 + r);
                }
                auto popIns = Disassemble::instruction(popBin);
                ChunkMutator(ins->getParent()).insertBeforeJumpTo(insPoint, popIns);
                insPoint = popIns;
            }
        }
    }
    else {
        std::vector<unsigned char> bin_add = {0x48, 0x83, 0xc4};
        for(int s = sizeof(int) * 4 - 8; s >= 0; s -= 8) {
            unsigned char c = (extendSize >> s) & 0xff;
            if(c) bin_add.push_back(c);
        }
        for(auto ins : frame->getEpilogueInstrs()) {
            ChunkMutator(ins->getParent()).insertBefore(ins,
                Disassemble::instruction(bin_add));
        }
    }
#endif
}

void StackExtendPass::addExtendStack(Function *function, FrameType *frame) {
#if defined(ARCH_AARCH64)
    auto firstB = function->getChildren()->getIterable()->get(0);
    if(!saveList.empty()) {
        auto reg1 = saveList[0];
        auto reg2 = saveList[1];
        // STP X29, X30, [SP, #-extendSize/8]
        auto enc = 0xA9800000 | (-extendSize/8 & 0x7F) << 15
            | reg2 << 10 | 31 << 5 | reg1;
        auto bin_stp = AARCH64InstructionBinary(enc);
        auto instr_stp = Disassemble::instruction(bin_stp.getVector());
        ChunkMutator(firstB).prepend(instr_stp);
    }
    else {
        auto bin_sub = AARCH64InstructionBinary(
            0xD1000000 | extendSize << 10 | 31 << 5 | 31);
        auto instr_sub = Disassemble::instruction(bin_sub.getVector());
        ChunkMutator(firstB).prepend(instr_sub);
    }

    auto bin_add = AARCH64InstructionBinary(
        0x91000000 | extendSize << 10 | 29 << 5 | 29);
    auto instr_add = Disassemble::instruction(bin_add.getVector());
    if(auto ins = frame->getSetBPInstr()) {
        ChunkMutator(ins->getParent()).insertAfter(ins, instr_add);
    }
#endif
}

void StackExtendPass::addShrinkStack(Function *function, FrameType *frame) {
#if defined(ARCH_AARCH64)
    auto bin_sub = AARCH64InstructionBinary(
        0xD1000000 | extendSize << 10 | 29 << 5 | 29);
    for(auto ins : frame->getResetSPInstrs()) {
        auto instr_sub = Disassemble::instruction(bin_sub.getVector());
        ChunkMutator(ins->getParent()).insertBefore(ins, instr_sub);
    }

    if(!saveList.empty()) {
        auto reg1 = saveList[0];
        auto reg2 = saveList[1];
        for(auto ins : frame->getEpilogueInstrs()) {
            // LDP X29, X30, [SP], #extendSize/8
            auto enc = 0xA8C00000 | extendSize/8 << 15
                | reg2 << 10 | 31 << 5 | reg1;
            auto bin_ldp = AARCH64InstructionBinary(enc);
            auto instr_ldp = Disassemble::instruction(bin_ldp.getVector());
            ChunkMutator(ins->getParent()).insertBefore(ins, instr_ldp);
            frame->fixEpilogue(ins, instr_ldp);
        }
    }
    else {
        for(auto ins : frame->getEpilogueInstrs()) {
            auto bin_add = AARCH64InstructionBinary(
                0x91000000 | extendSize << 10 | 31 << 5 | 31);
            auto instr_add = Disassemble::instruction(bin_add.getVector());
            ChunkMutator(ins->getParent()).insertBefore(ins, instr_add);
            frame->fixEpilogue(ins, instr_add);
        }
    }
#endif
}

FrameType::FrameType(Function *function) : setBPInstr(nullptr) {
    if(createsFrame(function)) {
        auto firstB = function->getChildren()->getIterable()->get(0);
        for(auto ins : firstB->getChildren()->getIterable()->iterable()) {
            if(auto assembly = ins->getSemantic()->getAssembly()) {
                auto asmOps = assembly->getAsmOperands();
#ifdef ARCH_X86_64
                if(assembly->getId() == X86_INS_MOV
                    && assembly->getAsmOperands()->getOpCount() == 2
                    && asmOps->getOperands()[0].type == X86_OP_REG
                    && asmOps->getOperands()[0].reg == X86_REG_RSP
                    && asmOps->getOperands()[1].type == X86_OP_REG
                    && asmOps->getOperands()[1].reg ==  X86_REG_RBP) {

                    setBPInstr = ins;
                    break;
                }
#elif defined(ARCH_AARCH64)
                if(asmOps->getOpCount() >= 2
                    && asmOps->getOperands()[0].type == ARM64_OP_REG
                    && asmOps->getOperands()[0].reg == ARM64_REG_X29
                    && asmOps->getOperands()[1].type == ARM64_OP_REG
                    && asmOps->getOperands()[1].reg == ARM64_REG_SP) {

                    if(assembly->getId() == ARM64_INS_MOV) {
                        setBPInstr = ins;
                    }
                    else if(assembly->getId() == ARM64_INS_ADD) {
                        setBPInstr = ins;
                    }
                    break;
                }
#endif
            }
        }
    }

    auto module = dynamic_cast<Module *>(function->getParent()->getParent());
    for(auto b : function->getChildren()->getIterable()->iterable()) {
        for(auto ins : b->getChildren()->getIterable()->iterable()) {
            if(dynamic_cast<ReturnInstruction *>(ins->getSemantic())) {
                epilogueInstrs.push_back(ins);
            }
            else if(auto cfi = dynamic_cast<ControlFlowInstruction *>(
                ins->getSemantic())) {

#ifdef ARCH_X86_64
                if(cfi->getMnemonic() == "callq") continue;
#elif defined(ARCH_AARCH64)
                if(cfi->getAssembly()->getId() == ARM64_INS_BL) continue;
#endif
                if(auto link = dynamic_cast<NormalLink *>(cfi->getLink())) {
                    if(auto f = dynamic_cast<Function *>(&*link->getTarget())) {
                        if(f != function) epilogueInstrs.push_back(ins);
                    }
                    continue;
                }
                if(dynamic_cast<PLTLink *>(cfi->getLink())) {
                    epilogueInstrs.push_back(ins);
                    continue;
                }
            }
            else if(dynamic_cast<IndirectJumpInstruction *>(
                ins->getSemantic())) {

                bool tablejump = false;
                for(auto jt : CIter::children(module->getJumpTableList())) {
                    if(ins == jt->getDescriptor()->getInstruction()) {
                        tablejump = true;
                        break;
                    }
                }
                if(!tablejump) epilogueInstrs.push_back(ins);
            }
        }
    }

    for(auto const &retInstr : epilogueInstrs) {
        auto parent = dynamic_cast<Block *>(retInstr->getParent());
        for(auto ins : parent->getChildren()->getIterable()->iterable()) {
            if(auto assembly = ins->getSemantic()->getAssembly()) {
                auto operands = assembly->getAsmOperands()->getOperands();
#ifdef ARCH_X86_64
                if(assembly->getId() == X86_INS_ADD
                    && assembly->getAsmOperands()->getOpCount() == 2
                    && operands[0].type == X86_OP_IMM
                    && operands[1].type == X86_OP_REG
                    && operands[1].reg == X86_REG_RSP) {

                    resetSPInstrs.push_back(ins);
                }
#elif defined(ARCH_AARCH64)
                if(assembly->getId() == ARM64_INS_MOV
                    && operands[0].reg == ARM64_REG_SP
                    && operands[1].type == ARM64_OP_REG
                    && operands[1].reg == ARM64_REG_X29) {

                    resetSPInstrs.push_back(ins);
                }
#endif
            }
        }
    }

    for(auto block : function->getChildren()->getIterable()->iterable()) {
        for(auto ins : block->getChildren()->getIterable()->iterable()) {
            if(auto cfi = dynamic_cast<ControlFlowInstruction *>(
                ins->getSemantic())) {

                for(auto ins : epilogueInstrs) {
                    if(cfi->getLink()->getTarget() == ins) {
                        jumpToEpilogueInstrs.push_back(cfi);
                        break;
                    }
                }
            }
        }
    }
}

bool FrameType::createsFrame(Function *function) {
#ifdef ARCH_X86_64
    for(auto block : CIter::children(function)) {
        for(auto ins : CIter::children(block)) {
            if(auto assembly = ins->getSemantic()->getAssembly()) {
                auto operands = assembly->getAsmOperands()->getOperands();
                if(assembly->getId() == X86_INS_PUSH) {
                    return true;
                }
                if(assembly->getId() == X86_INS_SUB
                    && assembly->getAsmOperands()->getOpCount() == 2
                    && operands[0].type == X86_OP_IMM
                    && operands[1].type == X86_OP_REG
                    && operands[1].reg == X86_REG_RSP) {

                    return true;
                }
            }
        }
    }
    return false;
#elif defined(ARCH_AARCH64)
    auto firstB = function->getChildren()->getIterable()->get(0);
    for(auto ins : firstB->getChildren()->getIterable()->iterable()) {
        if(auto assembly = ins->getSemantic()->getAssembly()) {
            auto operands = assembly->getAsmOperands()->getOperands();
            auto writeback = assembly->getAsmOperands()->getWriteback();
            if(assembly->getId() == ARM64_INS_SUB
                && operands[0].reg == ARM64_REG_SP) {

                return true;
            }
            else if(assembly->getId() == ARM64_INS_STP
                && operands[2].type == ARM64_OP_MEM
                && writeback) {

                return true;
            }
        }
    }
    return false;
#endif
}

void FrameType::fixEpilogue(Instruction *oldInstr, Instruction *newInstr) {
    for(auto &ins : epilogueInstrs) {
        if(ins == oldInstr) {
            *&ins = newInstr;
            break;
        }
    }

    for(auto cfi : jumpToEpilogueInstrs) {
        auto link = cfi->getLink();
        if(link->getTarget() == oldInstr) {
            cfi->setLink(new NormalLink(newInstr));
            delete link;
        }
    }
}

void FrameType::dump() {
    LOG(1, "BP set at " << (setBPInstr ? setBPInstr->getName() : ""));
    for(auto i : resetSPInstrs) {
        LOG(1, "SP reset at " << std::hex << i->getAddress());
    }
    for(auto i : epilogueInstrs) {
        LOG(1, "function epilogue starts at " << std::hex << i->getAddress());
    }
}

