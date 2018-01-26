#include <cassert>
#include "retpoline.h"
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
    for(auto block : CIter::children(function)) {
        for(auto instr : CIter::children(block)) {
            auto semantic = instr->getSemantic();
            if(dynamic_cast<IndirectJumpInstruction *>(semantic)) {
                auto trampoline = makeOutlinedTrampoline(module, instr);
                auto newSem = new ControlFlowInstruction(
                    X86_INS_JMP, instr, "\xe9", "jmpq", 4);
                newSem->setLink(new NormalLink(trampoline, Link::SCOPE_EXTERNAL_JUMP));
                instr->setSemantic(newSem);

                ChunkMutator(block, true).modifiedChildSize(instr,
                    newSem->getSize() - semantic->getSize());
                delete semantic;
            }
            else if(dynamic_cast<IndirectCallInstruction *>(semantic)) {
                auto trampoline = makeOutlinedTrampoline(module, instr);
                auto newSem = new ControlFlowInstruction(
                    X86_INS_CALL, instr, "\xe8", "callq", 4);
                newSem->setLink(new NormalLink(trampoline, Link::SCOPE_EXTERNAL_JUMP));
                instr->setSemantic(newSem);

                ChunkMutator(block, true).modifiedChildSize(instr,
                    newSem->getSize() - semantic->getSize());
                delete semantic;
            }
        }
    }
#endif
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
            nameStream << "r" << reg << "_r" << index; \
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
        }
    }

    module->getFunctionList()->getChildren()->add(function);
    module->getFunctionList()->getChildren()->clearSpatial();
    retpolineList[name] = function;
    return function;
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

    // movq OPERAND, (%rsp)
    // or movq COMPLEX, %mm1 + movq %mm1, (%rsp)
    std::vector<unsigned char> bin;
    if(semantic->hasMemoryOperand()) {
        if(indexReg == X86Register::INVALID) {
            // movq disp(%reg), %mm1
            bin.resize(3);
            bin[0] = 0x0f;
            bin[1] = 0x6f;
            if(reg >= 8) {
                bin[2] = 0x88 + reg - 8;
                if(reg == 12) {
                    bin.push_back(0x24);
                }
            }
            else {
                bin[2] = 0x88 + reg;
                if(reg == 4) {
                    bin.push_back(0x24);
                }
            }
            if(reg >= 8) bin.insert(bin.begin(), 0x41);
        }
        else {
            // movq disp(%reg, %index, scale), %mm1
            bin.resize(4);
            bin[0] = 0x0f;
            bin[1] = 0x6f;
            bin[2] = 0x8c;
            // scale | index(3) | base(3)
            size_t bits = 0;
            while(scale /= 2) bits++;
            unsigned char sib = bits << 6;
            if(reg >= 8) sib |= (reg - 8);
            else         sib |= reg;
            if(indexReg > 8) sib |= (indexReg - 8) << 3;
            else             sib |= indexReg << 3;
            bin[3] = sib;
            if(reg >= 8) bin.insert(bin.begin(), 0x41);
        }
        for(int i = 0; i < 4; i++) {
            bin.push_back(displacement & 0xff);
            displacement >>= 8;
        }

        static DisasmHandle handle(true);
        auto ins1 = DisassembleInstruction(handle).instruction(bin);

        // movq %mm1, (%rsp)
        auto ins2 = DisassembleInstruction(handle).instruction(
            (std::vector<unsigned char>){0x0f, 0x7f, 0x0c, 0x24});

        return {ins1, ins2};
    }
    else {
        // movq %reg, (%rsp)
        unsigned char rex = 0x48;
        if(reg >= 8) rex |= 0b0100;
        bin.push_back(rex);
        bin.push_back(0x89);
        unsigned char operand = 0x04;
        if(reg >= 8) operand |= (reg - 8) << 3;
        else         operand |= reg << 3;
        bin.push_back(operand);
        bin.push_back(0x24);
        static DisasmHandle handle(true);
        return {DisassembleInstruction(handle).instruction(bin)};
    }
#endif
}

std::vector<Instruction *> RetpolinePass::makeMovInstructionForJump(
    Instruction *instr) {

#ifdef ARCH_X86_64
    auto semantic = static_cast<IndirectJumpInstruction *>(instr->getSemantic());

    return makeMovInstruction(semantic);
#endif
}

std::vector<Instruction *> RetpolinePass::makeMovInstructionForCall(
    Instruction *instr) {

#ifdef ARCH_X86_64
    auto semantic = static_cast<IndirectCallInstruction *>(instr->getSemantic());

    return makeMovInstruction(semantic);
#endif
}
