#include <cassert>
#include "retpoline.h"
#include "chunk/dump.h"
#include "instr/concrete.h"
#include "instr/register.h"
#include "disasm/disassemble.h"
#include "operation/mutator.h"
#include "util/streamasstring.h"
#include "log/log.h"

void RetpolinePass::visit(Module *module) {
#ifdef ARCH_X86_64
    this->module = module;
    recurse(module->getFunctionList());
#endif
}

void RetpolinePass::visit(Function *function) {
#ifdef ARCH_X86_64
    if(function->getName().find("_ssse3") != std::string::npos) return;

    for(auto block : CIter::children(function)) {
        for(auto instr : CIter::children(block)) {
            auto semantic = instr->getSemantic();
            if(auto v = dynamic_cast<IndirectJumpInstruction *>(semantic)) {
                if(v->isForJumpTable()) continue;

                log_instruction(instr, "before:");

                auto trampoline = makeOutlinedTrampoline(module, instr);
                auto newSem = new ControlFlowInstruction(
                    X86_INS_JMP, instr, "\xe9", "jmpq", 4);
                newSem->setLink(new NormalLink(trampoline, Link::SCOPE_EXTERNAL_JUMP));
                instr->setSemantic(newSem);

                ChunkMutator(block, true).modifiedChildSize(instr,
                    newSem->getSize() - semantic->getSize());
                delete semantic;

                log_instruction(instr, "after: ");
            }
            else if(dynamic_cast<IndirectCallInstruction *>(semantic)) {
                log_instruction(instr, "before:");

                auto trampoline = makeOutlinedTrampoline(module, instr);
                auto newSem = new ControlFlowInstruction(
                    X86_INS_CALL, instr, "\xe8", "callq", 4);
                newSem->setLink(new NormalLink(trampoline, Link::SCOPE_EXTERNAL_JUMP));
                instr->setSemantic(newSem);

                ChunkMutator(block, true).modifiedChildSize(instr,
                    newSem->getSize() - semantic->getSize());
                delete semantic;

                log_instruction(instr, "after: ");
            }
        }
    }
    ChunkMutator(function, true);
#endif
}

void RetpolinePass::log_instruction(Instruction *instr, const char *message) {
    IF_LOG(10) {
        LOG0(1, "RetpolinePass: " << message << " ");
        ChunkDumper dump;
        instr->accept(&dump);
    }
}

Function *RetpolinePass::makeOutlinedTrampoline(Module *module, Instruction *instr) {
#ifdef ARCH_X86_64
    StreamAsString nameStream;
    nameStream << "retpoline_";

#define CONSTRUCT_NAME(v, nameStream) \
        if(!v->hasMemoryOperand()) { \
            auto reg = X86Register::convertToPhysical(v->getRegister()); \
            nameStream << "r" << reg; \
        } \
        else { \
            auto reg = X86Register::convertToPhysical(v->getRegister()); \
            auto index = X86Register::convertToPhysical(v->getIndexRegister()); \
            auto scale = v->getScale(); \
            auto disp = v->getDisplacement(); \
            nameStream << "mr" << reg; \
            if(index != X86Register::INVALID) nameStream << "_r" << index; \
            if(scale != 1) nameStream << "@" << scale; \
            if(disp != 0) nameStream << "$" << disp; \
        }

    auto semantic = instr->getSemantic();
    if(auto v = dynamic_cast<IndirectJumpInstruction *>(semantic)) {
        nameStream << "jmp_";
        CONSTRUCT_NAME(v, nameStream);
    }
    else if(auto v = dynamic_cast<IndirectCallInstruction *>(semantic)) {
        nameStream << "call_";
        CONSTRUCT_NAME(v, nameStream);
    }

    std::string name = nameStream;
    auto found = retpolineList.find(name);
    if(found != retpolineList.end()) return (*found).second;


    // retpoline_r11_trampoline:
    //   call set_up_target;
    // capture_spec:
    //   pause;
    //   jmp capture_spec;
    // set_up_target:
    //   mov %r11, (%rsp);
    //   ret;

    auto function = new Function();
    function->setName(name);
    function->setPosition(new AbsolutePosition(0x100));

    // XXX making a link to a block should be avoided
    {
        auto block1 = new Block();
        auto block2 = new Block();
        auto block3 = new Block();

        {
            ChunkMutator m(function);
            m.append(block1);
            m.append(block2);
            m.append(block3);
        }

        {
            auto callIns = new Instruction();
            auto callSem = new ControlFlowInstruction(
                X86_INS_CALL, callIns, "\xe8", "callq", 4);
            callSem->setLink(new NormalLink(block3, Link::SCOPE_WITHIN_FUNCTION));
            callIns->setSemantic(callSem);
            ChunkMutator(block1).append(callIns);
        }

        {
            auto pauseIns = Disassemble::instruction({0xf3, 0x90});

            auto jmpIns = new Instruction();
            auto jmpSem = new ControlFlowInstruction(
                X86_INS_JMP, jmpIns, "\xeb", "jmp", 1);
            jmpSem->setLink(new NormalLink(block2, Link::SCOPE_WITHIN_FUNCTION));
            jmpIns->setSemantic(jmpSem);

            ChunkMutator m(block2);
            m.append(pauseIns);
            m.append(jmpIns);
        }

        {
            std::vector<Instruction *> movInsList;
            if(dynamic_cast<IndirectJumpInstruction *>(semantic)) {
                movInsList = makeMovInstructionForJump(instr);
            }
            else if(dynamic_cast<IndirectCallInstruction *>(semantic)) {
                movInsList = makeMovInstructionForCall(instr);
            }

            if(movInsList.empty()) {
                LOG(1, "WARNING: couldn't rewrite " << instr->getName()
                    << " for retpoline! Using hlt instr");
                movInsList.push_back(Disassemble::instruction({0xf4}));
            }

            auto retIns = new Instruction();
            auto retSem = new ReturnInstruction();
            static DisasmHandle handle(true);
            retSem->setAssembly(AssemblyPtr(DisassembleInstruction(handle)
                .makeAssemblyPtr((std::vector<unsigned char>){0xc3})));
            retIns->setSemantic(retSem);

            ChunkMutator m(block3);
            for(auto ins : movInsList) m.append(ins);
            m.append(retIns);

#if 0
            for(auto i : movInsList) {
                ChunkDumper dump;
                i->accept(&dump);
            }
#endif
        }
    }

    module->getFunctionList()->getChildren()->add(function);
    module->getFunctionList()->getChildren()->clearSpatial();
    retpolineList[name] = function;
    return function;
#else
    return nullptr;
#endif
}

template <typename SemanticType>
static std::vector<Instruction *> makeMovInstruction(SemanticType *semantic) {
#ifdef ARCH_X86_64
    auto cs_reg = semantic->getRegister();
    assert(cs_reg != X86_REG_RIP);
    auto reg = X86Register::convertToPhysical(cs_reg);
    auto indexReg = X86Register::convertToPhysical(semantic->getIndexRegister());
    auto scale = semantic->getScale();
    int64_t displacement = semantic->getDisplacement();

    // movq EA, %r11
    std::vector<unsigned char> bin2;
    if(semantic->hasMemoryOperand()) {
        if(indexReg == X86Register::INVALID) {
            // movq disp(%reg), %r11
            bin2.resize(3);
            unsigned char rex = 0x4c;
            if(reg >= 8) rex |= 0b0001;
            bin2[0] = rex;
            bin2[1] = 0x8b;
            if(reg >= 8) {
                bin2[2] = 0x98 + reg - 8;
                //bin2[2] = 0x80 | (reg - 8) << 3 | (reg - 8);
                if(reg == 12) {
                    bin2.push_back(0x24);
                }
            }
            else {
                bin2[2] = 0x98 + reg;
                //bin2[2] = 0x80 | reg << 3 | reg;
                if(reg == 4) {
                    bin2.push_back(0x24);
                }
            }
        }
        else {
            // movq disp(%reg, %index, scale), %r11
            bin2.resize(4);
            unsigned char rex = 0x4c;
            if(reg >= 8) rex |= 0b0001;
            if(indexReg >= 8) rex |= 0b0010;
            bin2[0] = rex;
            bin2[1] = 0x8b;
            //unsigned char operand = 0x84;
            //if(reg >= 8) operand |= (reg - 8) << 3;
            //else         operand |= reg << 3;
            unsigned char operand = 0x9c;
            bin2[2] = operand;
            // scale | index(3) | base(3)
            size_t bits = 0;
            while(scale /= 2) bits++;
            unsigned char sib = bits << 6;
            if(reg >= 8) sib |= (reg - 8);
            else         sib |= reg;
            if(indexReg > 8) sib |= (indexReg - 8) << 3;
            else             sib |= indexReg << 3;
            bin2[3] = sib;
        }
        for(int i = 0; i < 4; i++) {
            bin2.push_back(displacement & 0xff);
            displacement >>= 8;
        }
    }
    else {
        // movq %reg, %r11
        unsigned char rex = 0x49;
        if(reg >= 8) rex |= 0b0100;
        bin2.push_back(rex);
        bin2.push_back(0x89);
        unsigned char operand = 0xc3;
        if(reg >= 8) operand |= (reg - 8) << 3;
        else         operand |= reg << 3;
        bin2.push_back(operand);
    }
    DisasmHandle handle(true);
    auto ins1 = DisassembleInstruction(handle).instruction(bin2);

    // movq %r11, (%rsp)
    std::vector<unsigned char> bin4{0x4c, 0x89, 0x1c, 0x24};
    auto ins2 = DisassembleInstruction(handle).instruction(bin4);
    return {ins1, ins2};
#else
    return {};
#endif
}

std::vector<Instruction *> RetpolinePass::makeMovInstructionForJump(
    Instruction *instr) {

#ifdef ARCH_X86_64
    auto semantic = static_cast<IndirectJumpInstruction *>(instr->getSemantic());

    return makeMovInstruction(semantic);
#else
    return {};
#endif
}

std::vector<Instruction *> RetpolinePass::makeMovInstructionForCall(
    Instruction *instr) {

#ifdef ARCH_X86_64
    auto semantic = static_cast<IndirectCallInstruction *>(instr->getSemantic());

    return makeMovInstruction(semantic);
#else
    return {};
#endif
}
