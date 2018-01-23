#include "retpoline.h"
#include "instr/concrete.h"
#include "disasm/disassemble.h"
#include "operation/mutator.h"
#include "util/streamasstring.h"

void RetpolinePass::visit(Module *module) {
    this->module = module;
    recurse(module->getFunctionList());
}

void RetpolinePass::visit(Function *function) {
    for(auto block : CIter::children(function)) {
        for(auto instr : CIter::children(block)) {
            auto semantic = instr->getSemantic();
            if(dynamic_cast<IndirectJumpInstruction *>(semantic)) {
                auto trampoline = makeOutlinedTrampoline(module, instr);
                auto newSem = new ControlFlowInstruction(
                    X86_INS_JMP, instr, "\xe9", "jmpq", 4);
                newSem->setLink(new NormalLink(trampoline, Link::SCOPE_EXTERNAL_JUMP));
                instr->setSemantic(newSem);
                delete semantic;
            }
            else if(dynamic_cast<IndirectCallInstruction *>(semantic)) {
                auto trampoline = makeOutlinedTrampoline(module, instr);
                auto newSem = new ControlFlowInstruction(
                    X86_INS_CALL, instr, "\xe8", "callq", 4);
                newSem->setLink(new NormalLink(trampoline, Link::SCOPE_EXTERNAL_JUMP));
                instr->setSemantic(newSem);
                delete semantic;
            }
        }
    }
}

Function *RetpolinePass::makeOutlinedTrampoline(Module *module, Instruction *instr) {
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
            auto movIns = makeMovInstruction(instr);

            auto retIns = new Instruction();
            auto retSem = new ReturnInstruction();
            static DisasmHandle handle(true);
            retSem->setAssembly(AssemblyPtr(DisassembleInstruction(handle)
                .makeAssemblyPtr((std::vector<unsigned char>){0xc3})));
            retIns->setSemantic(retSem);

            ChunkMutator m(block3);
            m.append(movIns);
            m.append(retIns);
        }
    }

    module->getFunctionList()->getChildren()->add(function);
    module->getFunctionList()->getChildren()->clearSpatial();
    retpolineList[name] = function;
    return function;
}

Instruction *RetpolinePass::makeMovInstruction(Instruction *instr) {
    return Disassemble::instruction({0xf4});  // hlt for now (not implemented)
}
