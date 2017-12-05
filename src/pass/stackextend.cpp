#include <algorithm>
#include <string>
#include <assert.h>
#include "stackextend.h"
#include "analysis/frametype.h"
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
static std::tuple<bool, size_t> getStackOffset(UDState *state) {
    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternPhysicalRegisterIs<X86Register::SP>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > StackAccessForm1;

    typedef TreePatternBinary<TreeNodeSubtraction,
        TreePatternPhysicalRegisterIs<X86Register::SP>,
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
            return std::make_tuple(true, c->getValue());
        }
        if(StackDerefForm2::matches(def.second, cap2)) {
            auto c = dynamic_cast<TreeNodeConstant *>(cap2.get(0));
            return std::make_tuple(true, c->getValue());
        }

        // add/sub $0x10,%rsp or lea 0x8(%rsp),%rdi
        if(StackAccessForm1::matches(def.second, cap1)) {
            auto semantic = state->getInstruction()->getSemantic();
            if(semantic->getAssembly()->getId() == X86_INS_LEA) {
                auto c = dynamic_cast<TreeNodeConstant *>(cap1.get(0));
                return std::make_tuple(true, c->getValue());
            }
            return std::make_tuple(true, 0);
        }
        if(StackAccessForm2::matches(def.second, cap2)) {
            auto semantic = state->getInstruction()->getSemantic();
            if(semantic->getAssembly()->getId() == X86_INS_LEA) {
                auto c = dynamic_cast<TreeNodeConstant *>(cap2.get(0));
                return std::make_tuple(true, c->getValue());
            }
            return std::make_tuple(true, 0);
        }
    }
    for(auto& def : state->getMemDefList()) {
        TreeCapture cap1, cap2;
        if(StackAccessForm1::matches(def.second, cap1)) {
            auto c = dynamic_cast<TreeNodeConstant *>(cap1.get(0));
            return std::make_tuple(true, c->getValue());
        }
        if(StackAccessForm2::matches(def.second, cap2)) {
            auto c = dynamic_cast<TreeNodeConstant *>(cap2.get(0));
            return std::make_tuple(true, c->getValue());
        }
    }
    //state->dumpState();
    return std::make_tuple(false, 0);
    //throw "getStackOffset: error";
    //return 0;
}

static size_t getCurrentFrameSize(UDState *state) {
    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternPhysicalRegisterIs<X86Register::SP>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > StackAccessForm1;

    typedef TreePatternBinary<TreeNodeSubtraction,
        TreePatternPhysicalRegisterIs<X86Register::SP>,
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
        FlowUtil::searchUpDef<StackAccessForm1>(state, X86Register::SP, f);
        if(!searching) {
            FlowUtil::searchUpDef<StackAccessForm2>(state, X86Register::SP, f);
        }
    } while(searching);
    return size;
}
#endif

void StackExtendPass::adjustOffset(Instruction *instruction) {
#ifdef ARCH_X86_64
    LOG(1, "adjusting displacement in "
        << std::hex << instruction->getAddress());

    auto semantic = instruction->getSemantic();

    auto sfi = new StackFrameInstruction(semantic->getAssembly());
    sfi->addToDisplacementValue(extendSize);
    instruction->setSemantic(sfi);
    delete semantic;
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

    //TemporaryLogLevel tll("analysis", 11);
    SccOrder order(&cfg);
    order.genFull(0);
    usedef.analyze(order.get());

    //TemporaryLogLevel tll2("pass", 10, function->hasName("egalito_hook_jit_fixup"));

    for(auto block : CIter::children(function)) {
        for(auto instr : CIter::children(block)) {
            auto state = working.getState(instr);
            LOG(10, "/// " << std::hex << instr->getAddress());
            IF_LOG(10) state->dumpState();
            if(state->getRegDef(X86Register::SP)) {
                continue;   // skip push & pop
            }

            bool found;
            size_t offset;
            std::tie(found, offset) = getStackOffset(state);
            if(found) {
                auto frameSize = getCurrentFrameSize(state);
                LOG(10, "offset = " << offset
                    << " frame size = " << frameSize);
                if(frameSize <= offset) {
                    adjustOffset(instr);
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

