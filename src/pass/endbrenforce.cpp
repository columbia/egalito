#include <vector>
#include <cassert>
#include "endbrenforce.h"
#include "disasm/disassemble.h"
#include "instr/register.h"
#include "instr/concrete.h"
#include "operation/mutator.h"
#include "types.h"

template <typename SemanticType>
static Instruction *makeMovR11Instruction(SemanticType *semantic) {
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

    return ins1;
#else
    return nullptr;
#endif
}

void EndbrEnforcePass::visit(Module *module) {
#ifdef ARCH_X86_64
    auto instr = Disassemble::instruction({0x0f, 0x0b});  // ud2
    auto block = new Block();

    auto symbol = new Symbol(0x0, 0, "egalito_endbr_violation",
       Symbol::TYPE_FUNC, Symbol::BIND_GLOBAL, 0, 0);
    auto function = new Function(symbol);
    function->setName(symbol->getName());
    function->setPosition(new AbsolutePosition(0x0));

    module->getFunctionList()->getChildren()->add(function);
    function->setParent(module->getFunctionList());
    ChunkMutator(function).append(block);
    ChunkMutator(block).append(instr);

    this->violationTarget = function;
    recurse(module);
#endif
}

void EndbrEnforcePass::visit(Function *function) {
    // in StaticGen, these functions call back into the loader
    if(function->getName() == "_dl_vdso_vsym") return;
    if(function->getName() == "_dl_addr") return;
    if(function->getName() == "__run_exit_handlers") return;

    // we currently allow longjmp to go anywhere instead of identifying
    // setjmp calls
    if(function->getName() == "__longjmp") return;
    if(function->getName() == "____longjmp_chk") return;

    recurse(function);
}

void EndbrEnforcePass::visit(Instruction *instruction) {
    auto semantic = instruction->getSemantic();
    if(auto v = dynamic_cast<IndirectJumpInstruction *>(semantic)) {
        //if(!v->isForJumpTable()) {
            makeEnforcementCode(instruction);
        //}
    }
    else if(dynamic_cast<IndirectCallInstruction *>(semantic)) {
        makeEnforcementCode(instruction);
    }
}

void EndbrEnforcePass::makeEnforcementCode(Instruction *point) {
#ifdef ARCH_X86_64
    //    0:   f3 0f 1e fa             endbr64

    //    4:   49 89 c3                mov    %rax, %r11
    //    7:   41 81 3b f3 0f 1e fa    cmpl   $0xfa1e0ff3, (%r11)
    //    e:   0f 85 00 00 00 00       jne    __ERROR

    // mov WHATEVER, %r11
    Instruction *movInstr = nullptr;
    auto semantic = point->getSemantic();
    if(auto v = dynamic_cast<IndirectJumpInstruction *>(semantic)) {
        movInstr = makeMovR11Instruction(v);
    }
    else if(auto v = dynamic_cast<IndirectCallInstruction *>(semantic)) {
        movInstr = makeMovR11Instruction(v);
    }

    // 41 81 3b f3 0f 1e fa    cmpl   $0xfa1e0ff3, (%r11)
    auto cmpInstr = Disassemble::instruction({0x41, 0x81, 0x3b, 0xf3, 0x0f, 0x1e, 0xfa});

    // jne
    auto jne = new Instruction();
    auto jneSem = new ControlFlowInstruction(
        X86_INS_JNE, jne, "\x0f\x85", "jnz", 4);
    jneSem->setLink(new NormalLink(violationTarget, Link::SCOPE_EXTERNAL_JUMP));
    jne->setSemantic(jneSem);

    {
        ChunkMutator m(point->getParent(), true);
        m.insertBeforeJumpTo(point, movInstr);  // swaps point & movInstr
        std::swap(point, movInstr);

        m.insertAfter(movInstr, cmpInstr);
        m.insertAfter(cmpInstr, jne);
    }

    // jmpq *%r11 / callq *%r11
    static DisasmHandle handle(true);
    AssemblyPtr newAssembly;
    InstructionSemantic *newSem = nullptr;
    if(dynamic_cast<IndirectJumpInstruction *>(semantic)) {
        newAssembly = DisassembleInstruction(handle, true).makeAssemblyPtr(
            std::vector<unsigned char>{0x41, 0xff, 0xe3});
        newSem = new IndirectJumpInstruction(X86_REG_R11, "jmpq");
    }
    else if(dynamic_cast<IndirectCallInstruction *>(semantic)) {
        newAssembly = DisassembleInstruction(handle, true).makeAssemblyPtr(
            std::vector<unsigned char>{0x41, 0xff, 0xd3});
        newSem = new IndirectCallInstruction(X86_REG_R11);
    }
    newSem->setAssembly(newAssembly);
    point->setSemantic(newSem);
    ChunkMutator(point->getParent(), true).modifiedChildSize(point,
        newSem->getSize() - semantic->getSize());
    delete semantic;
#endif
}
