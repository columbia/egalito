#include <cassert>
#include <cstring>
#include "usegstable.h"
#include "chunk/concrete.h"
#include "instr/concrete.h"
#include "operation/find2.h"
#include "operation/mutator.h"
#include "disasm/disassemble.h"
#include "chunk/dump.h"
#include "log/log.h"
#include "log/temp.h"

void UseGSTablePass::visit(Module *module) {
    //TemporaryLogLevel tll("pass", 10, module->getName() == "module-(egalito)");
    LOG(1, "UseGSTablePass " << module->getName());
    recurse(module->getDataRegionList());
    recurse(module->getVTableList());
    recurse(module);
}

void UseGSTablePass::visit(Function *function) {
    //TemporaryLogLevel tll("pass", 11, function->hasName("ifunc_resolver"));
    //TemporaryLogLevel tll("pass", 10);
    // already uses gs
    if(!function->hasName("egalito_hook_jit_fixup")) {
        recurse(function);
    }
}

void UseGSTablePass::visit(Block *block) {
    std::vector<Instruction *> pointerLinks;
    if(transformIndirectCalls) {
        for(auto instr : CIter::children(block)) {
            auto semantic = instr->getSemantic();
            if(auto v = dynamic_cast<LinkedInstruction *>(semantic)) {
                if(auto link = v->getLink()) {
                    if(dynamic_cast<ExternalNormalLink *>(link)
                        || dynamic_cast<ExternalOffsetLink *>(link)
                        || dynamic_cast<ExternalAbsoluteNormalLink *>(link)) {

                        pointerLinks.push_back(instr);
                    }
                }
            }
        }
        for(auto instr : pointerLinks) {
            redirectLinks(instr);
        }
    }

    std::vector<std::pair<Block *, Instruction *>> directCalls;
    std::vector<std::pair<Block *, Instruction *>> tailRecursions;
    std::vector<std::pair<Block *, Instruction *>> indirectCalls;
    std::vector<std::pair<Block *, Instruction *>> indirectTailRecursions;

    std::vector<std::pair<Block *, Instruction *>> RIPrelativeCalls;
    std::vector<std::pair<Block *, Instruction *>> RIPrelativeJumps;

    ChunkDumper d;
    for(auto instr : CIter::children(block)) {
        IF_LOG(11) {
            instr->accept(&d);
        }
        auto semantic = instr->getSemantic();
        if(auto v = dynamic_cast<ControlFlowInstruction *>(semantic)) {
            if(v->getMnemonic() == "callq") {
                if(transformDirectCalls) directCalls.emplace_back(block, instr);
            }
            else if(auto link = v->getLink()) {
                if(dynamic_cast<ExternalNormalLink *>(link)
                    || dynamic_cast<ExternalOffsetLink *>(link)
                    || dynamic_cast<ExternalAbsoluteNormalLink *>(link)) {

                    tailRecursions.emplace_back(block, instr);
                }
            }
        }
        if(dynamic_cast<IndirectCallInstruction *>(semantic)) {
            if(transformIndirectCalls) indirectCalls.emplace_back(block, instr);
        }
        if(auto v = dynamic_cast<IndirectJumpInstruction *>(semantic)) {
            if(!v->isForJumpTable()) {
                if(transformIndirectCalls) {    //!!!
                    indirectTailRecursions.emplace_back(block, instr);
                }
            }
        }
        if(auto v = dynamic_cast<LinkedInstruction *>(semantic)) {
            auto assembly = v->getAssembly();
            if(assembly->getId() == X86_INS_CALL) {
                RIPrelativeCalls.emplace_back(block, instr);
            }
            if(assembly->getId() == X86_INS_JMP) {
                RIPrelativeJumps.emplace_back(block, instr);
            }
        }
    }

    for(auto pair : directCalls) {
        rewriteDirectCall(pair.first, pair.second);
    }
    for(auto pair : tailRecursions) {
        rewriteTailRecursion(pair.first, pair.second);
    }
    for(auto pair : indirectCalls) {
        rewriteIndirectCall(pair.first, pair.second);
    }
    for(auto pair : indirectTailRecursions) {
        rewriteIndirectTailRecursion(pair.first, pair.second);
    }
    for(auto pair : RIPrelativeCalls) {
        rewriteRIPrelativeCall(pair.first, pair.second);
    }
    for(auto pair : RIPrelativeJumps) {
        rewriteRIPrelativeJump(pair.first, pair.second);
    }
}

void UseGSTablePass::redirectLinks(Instruction *instr) {
    auto i = static_cast<LinkedInstruction *>(instr->getSemantic());
    auto link = i->getLink();
    if(link) return;

    Chunk *target = &*link->getTarget();
    if(target == nullptr) {
        LOG(1, "WARNING: unknown pointer target "
            << instr->getName()
            << ", not transforming for gs table");
        return;
    }

    LOG0(1, "redirectLinks ");
    ChunkDumper d;
    instr->accept(&d);

    if(dynamic_cast<Function *>(target)) {  // otherwise table jump base?
        auto gsEntry = gsTable->makeEntryFor(target);
        i->setLink(new GSTableLink(gsEntry));
        delete link;
    }
}

static uint32_t directCallID = 0;
static uint32_t directTailJumpID = 1;
static uint32_t indirectCallID = 2;
static uint32_t indirectTailJumpID = 3;

void UseGSTablePass::rewriteDirectCall(Block *block, Instruction *instr) {
    LOG0(10, "    rewriting direct call");
    IF_LOG(10) {
        ChunkDumper d;
        instr->accept(&d);
    }
    auto i = static_cast<ControlFlowInstruction *>(instr->getSemantic());
    if(!i->getLink()) return;

    Chunk *target = &*i->getLink()->getTarget();
    if(target == nullptr) {
        LOG(10, "WARNING: unknown target for direct call " << instr->getName()
            << ", not transforming for gs table");
        return;
    }

#ifdef ARCH_X86_64
    // callq  *%gs:0xdeadbeef
    DisasmHandle handle(true);
    auto assembly = DisassembleInstruction(handle).makeAssembly(
        {0x65, 0xff, 0x14, 0x25, 0, 0, 0, 0});
    auto semantic = new LinkedInstruction(instr, assembly);

    //can be PLTTrampoline
    //assert(dynamic_cast<Function *>(target));
    auto gsEntry = gsTable->makeEntryFor(target);
    semantic->setLink(new GSTableLink(gsEntry));
    semantic->setIndex(0);  // !!!
    instr->setSemantic(semantic);

    ChunkMutator(block).modifiedChildSize(instr,
        semantic->getSize() - i->getSize());
    delete i;

    // movq ID, %mm0
    std::vector<unsigned char> bin{0x0f, 0x64, 0x04, 0x25, 0, 0, 0, 0};
    auto tmp = &directCallID;
    std::memcpy(&bin[4], &tmp, 4);
    auto movID = DisassembleInstruction(handle).instruction(bin);

    // movd offset = 0x4(%rip), %mm1
    auto movOffset = DisassembleInstruction(handle).instruction(
        std::vector<unsigned char>({0x0f, 0x6e, 0x0d, 0x04, 0, 0, 0}));

    ChunkMutator(block).insertBeforeJumpTo(instr, movID);
    ChunkMutator(block).insertAfter(instr, movOffset);
#endif
}

void UseGSTablePass::rewriteTailRecursion(Block *block, Instruction *instr) {
    LOG0(10, "    rewriting tail recursion");
    IF_LOG(10) {
        ChunkDumper d;
        instr->accept(&d);
    }

    auto i = static_cast<ControlFlowInstruction *>(instr->getSemantic());
    if(!i->getLink()) return;

    Chunk *target = &*i->getLink()->getTarget();
    if(target == nullptr) {
        LOG(10, "WARNING: unknown target for tail recursion "
            << instr->getName()
            << ", not transforming for gs table");
        return;
    }

#ifdef ARCH_X86_64
    DisasmHandle handle(true);
    // jmpq *%gs:0xdeadbeef
    auto assembly = DisassembleInstruction(handle).makeAssembly(
        {0x65, 0xff, 0x24, 0x25, 0, 0, 0, 0});
    auto semantic = new LinkedInstruction(instr, assembly);

    // assert(dynamic_cast<Function *>(target));
    auto gsEntry = gsTable->makeEntryFor(target);
    semantic->setLink(new GSTableLink(gsEntry));
    semantic->setIndex(0);  // !!!
    instr->setSemantic(semantic);

    ChunkMutator(block).modifiedChildSize(instr,
        semantic->getSize() - i->getSize());
    delete i;

#if 0
    // movq %r11, %xmm8
    auto mov = DisassembleInstruction(handle).instruction(
        std::vector<unsigned char>({0x66, 0x4d, 0x0f, 0x6e, 0xc3}));
    ChunkMutator(block).insertBeforeJumpTo(instr, mov);
    // instr == mov!!

    // lea 0x5(%rip), %r11
    auto leaR11 = DisassembleInstruction(handle).instruction(
        std::vector<unsigned char>({0x4c, 0x8d, 0x1d, 0x05, 0, 0, 0}));
    ChunkMutator(block).insertBefore(instr, leaR11);
#endif
    // movq ID, %mm0
    std::vector<unsigned char> bin{0x0f, 0x64, 0x04, 0x25, 0, 0, 0, 0};
    auto tmp = &directTailJumpID;
    std::memcpy(&bin[4], &tmp, 4);
    auto movID = DisassembleInstruction(handle).instruction(bin);

    // movd offset = 0x4(%rip), %mm1
    auto movOffset = DisassembleInstruction(handle).instruction(
        std::vector<unsigned char>({0x0f, 0x6e, 0x0d, 0x04, 0, 0, 0}));

    ChunkMutator(block).insertBeforeJumpTo(instr, movID);
    ChunkMutator(block).insertAfter(instr, movOffset);
#endif
}

void UseGSTablePass::rewriteIndirectCall(Block *block, Instruction *instr) {
    //TemporaryLogLevel tll("pass", 10);
    LOG0(10, "rewriteIndirectCall");
    IF_LOG(10) {
        TemporaryLogLevel tll("disasm", 10);
        ChunkDumper d;
        instr->accept(&d);
    }
#ifdef ARCH_X86_64
    auto i = static_cast<IndirectCallInstruction *>(instr->getSemantic());
    auto cs_reg = i->getRegister();
    assert(cs_reg != X86_REG_RIP);
    auto reg = X86Register::convertToPhysical(cs_reg);
    auto indexReg = X86Register::convertToPhysical(i->getIndexRegister());
    auto scale = i->getScale();
    int64_t displacement = i->getDisplacement();

    DisasmHandle handle(true);

    // %reg should not be overwritten for call!!
#if 0
    if(reg == X86Register::SP) {
        cs_reg = X86_REG_R11;
        reg = X86Register::R11;
    }

    // callq  *%gs:(%reg)
    std::vector<unsigned char> bin{0x65};
    if(reg >= 8) {
        bin.push_back(0x41); bin.push_back(0xff);
        if(reg == 12) {
            bin.push_back(0x14); bin.push_back(0x24);
        }
        else if(reg == 13) {
            bin.push_back(0x55); bin.push_back(0x00);
        }
        else {
            bin.push_back(reg + 0x10);
        }
    }
    else {
        bin.push_back(0xff);
        if(reg == 5) {
            bin.push_back(0x55); bin.push_back(0x00);
        }
        else {
            bin.push_back(reg + 0x10);
        }
    }
    auto assembly = DisassembleInstruction(handle).makeAssembly(bin);
    auto semantic = new IndirectCallInstruction(assembly, cs_reg);
    instr->setSemantic(semantic);
    ChunkMutator(block).modifiedChildSize(instr,
        semantic->getSize() - i->getSize());

    // movq EA, %reg
    std::vector<unsigned char> bin2;
    if(indexReg == X86Register::INVALID) {
        // movq disp(%reg), %reg
        bin2.resize(3);
        unsigned char rex = 0x48;
        if(reg >= 8) rex |= 0b0101;
        bin2[0] = rex;
        bin2[1] = 0x8b;
        if(reg >= 8) {
            //bin2[2] = 0x98 + reg - 8;
            bin2[2] = 0x80 | (reg - 8) << 3 | (reg - 8);
            if(reg == 12) {
                bin2.push_back(0x24);
            }
        }
        else {
            //bin2[2] = 0x98 + reg;
            bin2[2] = 0x80 | reg << 3 | reg;
            if(reg == 4) {
                bin2.push_back(0x24);
            }
        }
    }
    else {
        // movq disp(%reg, %index, scale), %reg
        bin2.resize(4);
        unsigned char rex = 0x48;
        if(reg >= 8) rex |= 0b0101;
        if(indexReg >= 8) rex |= 0b0010;
        bin2[0] = rex;
        bin2[1] = 0x8b;
        unsigned char operand = 0x84;
        if(reg >= 8) operand |= (reg - 8) << 3;
        else         operand |= reg << 3;
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
    auto movEA = DisassembleInstruction(handle).instruction(bin2);

    // movq ID, %mm0
    std::vector<unsigned char> bin3{0x0f, 0x64, 0x04, 0x25, 0, 0, 0, 0};
    auto tmp = &indirectCallID;
    std::memcpy(&bin3[4], &tmp, 4);
    auto movID = DisassembleInstruction(handle).instruction(bin3);

    // movq %reg, %mm1
    std::vector<unsigned char> bin4;
    if(reg >= 8) bin4.push_back(0x49);
    else         bin4.push_back(0x48);
    bin4.push_back(0x0f); bin4.push_back(0x6e);
    if(reg >= 8) bin4.push_back(reg + 0xc0);
    else         bin4.push_back(reg + 0xc0 + 8);
    auto movOffset = DisassembleInstruction(handle).instruction(bin4);
#else
    // callq  *%gs:(%r11)
    std::vector<unsigned char> bin{0x65, 0x41, 0xff, 0x13};
    auto assembly = DisassembleInstruction(handle).makeAssembly(bin);
    auto semantic = new IndirectCallInstruction(assembly, X86_REG_R11);
    instr->setSemantic(semantic);
    ChunkMutator(block).modifiedChildSize(instr,
        semantic->getSize() - i->getSize());

    std::vector<unsigned char> bin2;
    if(i->hasMemoryOperand()) {
        // movq EA, %r11
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
        if(reg >= 8) rex |= 0b0010;
        bin2.push_back(rex);
        bin2.push_back(0x89);
        unsigned char operand = 0xc3;
        if(reg >= 8) operand |= (reg - 8) << 3;
        else         operand |= reg << 3;
        bin2.push_back(operand);
    }
    auto movEA = DisassembleInstruction(handle).instruction(bin2);

    // movq ID, %mm0
    std::vector<unsigned char> bin3{0x0f, 0x64, 0x04, 0x25, 0, 0, 0, 0};
    auto tmp = &indirectCallID;
    std::memcpy(&bin3[4], &tmp, 4);
    auto movID = DisassembleInstruction(handle).instruction(bin3);

    // movq %r11, %mm1
    std::vector<unsigned char> bin4{0x49, 0x0f, 0x6e, 0xcb};
    auto movOffset = DisassembleInstruction(handle).instruction(bin4);
#endif

    ChunkMutator(block).insertBeforeJumpTo(instr, movEA);
    ChunkMutator(block).insertAfter(instr, movID);
    ChunkMutator(block).insertAfter(instr, movOffset);

    delete i;
#endif
}

void UseGSTablePass::rewriteIndirectTailRecursion(Block *block,
    Instruction *instr) {

    LOG(10, "    rewriting indirect tail recursion "
        << std::hex << instr->getAddress());
    IF_LOG(10) {
        ChunkDumper d;
        instr->accept(&d);
    }

#ifdef ARCH_X86_64
    auto i = static_cast<IndirectJumpInstruction *>(instr->getSemantic());
    auto cs_reg = i->getRegister();
    auto reg = X86Register::convertToPhysical(cs_reg);
    auto indexReg = X86Register::convertToPhysical(i->getIndexRegister());
    auto scale = i->getScale();
    int64_t displacement = i->getDisplacement();

    DisasmHandle handle(true);

    // %reg should not be overwritten for PLT
#if 0
    if(reg == X86Register::SP) {
        LOG(0, "rewriteIndirectTail cannot handle this case");
    }

    // jmpq  *%gs:(%reg)
    std::vector<unsigned char> bin{0x65};
    if(reg >= 8) {
        bin.push_back(0x41); bin.push_back(0xff);
        if(reg == 12) {
            bin.push_back(reg + 0x20 - 8); bin.push_back(0x24);
        }
        if(reg == 13) {
            bin.push_back(0x65); bin.push_back(0x00);
        }
        else {
            bin.push_back(reg + 0x20 - 8);
        }
    }
    else {
        bin.push_back(0xff);
        if(reg == 5) {  // RBP
            bin.push_back(0x65); bin.push_back(0x00);
        }
        else {
            bin.push_back(reg + 0x20);
        }
    }
    auto assembly = DisassembleInstruction(handle).makeAssembly(bin);
    auto semantic = new IndirectJumpInstruction(assembly, i->getRegister(),
        "jmpq");
    instr->setSemantic(semantic);
    ChunkMutator(block).modifiedChildSize(instr,
        semantic->getSize() - i->getSize());

    Instruction *movEA = nullptr;
    if(i->hasMemoryOperand()) {
        // movq EA, %reg
        std::vector<unsigned char> bin2;
        if(indexReg == X86Register::INVALID) {
            // movq disp(%reg), %reg
            bin2.resize(3);
            unsigned char rex = 0x48;
            if(reg >= 8) rex |= 0b0101;
            bin2[0] = rex;
            bin2[1] = 0x8b;
            if(reg >= 8) {
                //bin2[2] = 0x98 + reg - 8;
                bin2[2] = 0x80 | (reg - 8) << 3 | (reg - 8);
                if(reg == 12) {
                    bin2.push_back(0x24);
                }
            }
            else {
                //bin2[2] = 0x98 + reg;
                bin2[2] = 0x80 | reg << 3 | reg;
                if(reg == 4) {
                    bin2.push_back(0x24);
                }
            }
        }
        else {
            // movq disp(%reg, %index, scale), %reg
            bin2.resize(4);
            unsigned char rex = 0x48;
            if(reg >= 8) rex |= 0b0101;
            if(indexReg >= 8) rex |= 0b0010;
            bin2[0] = rex;
            bin2[1] = 0x8b;
            unsigned char operand = 0x84;
            if(reg >= 8) operand |= (reg - 8) << 3;
            else         operand |= reg << 3;
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
        movEA = DisassembleInstruction(handle).instruction(bin2);
    }

    // movq ID, %mm0
    std::vector<unsigned char> bin3{0x0f, 0x64, 0x04, 0x25, 0, 0, 0, 0};
    auto tmp = &indirectTailJumpID;
    std::memcpy(&bin3[4], &tmp, 4);
    auto movID = DisassembleInstruction(handle).instruction(bin3);

    // movq %reg, %mm1
    std::vector<unsigned char> bin4;
    if(reg >= 8) bin4.push_back(0x49);
    else         bin4.push_back(0x48);
    bin4.push_back(0x0f); bin4.push_back(0x6e);
    if(reg >= 8) bin4.push_back(reg + 0xc0);
    else         bin4.push_back(reg + 0xc0 + 8);
    auto movOffset = DisassembleInstruction(handle).instruction(bin4);
#else
    // jmpq  *%gs:(%r11)
    std::vector<unsigned char> bin{0x65, 0x41, 0xff, 0x23};
    auto assembly = DisassembleInstruction(handle).makeAssembly(bin);
    auto semantic = new IndirectJumpInstruction(assembly, i->getRegister(),
        "jmpq");
    instr->setSemantic(semantic);
    ChunkMutator(block).modifiedChildSize(instr,
        semantic->getSize() - i->getSize());

    Instruction *movEA = nullptr;
    if(i->hasMemoryOperand()) {
        // movq EA, %r11
        std::vector<unsigned char> bin2;
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
        movEA = DisassembleInstruction(handle).instruction(bin2);
    }

    // movq ID, %mm0
    std::vector<unsigned char> bin3{0x0f, 0x64, 0x04, 0x25, 0, 0, 0, 0};
    auto tmp = &indirectTailJumpID;
    std::memcpy(&bin3[4], &tmp, 4);
    auto movID = DisassembleInstruction(handle).instruction(bin3);

    // movq %r11, %mm1
    std::vector<unsigned char> bin4{0x49, 0x0f, 0x6e, 0xcb};
    auto movOffset = DisassembleInstruction(handle).instruction(bin4);
#endif

    if(movEA) {
        ChunkMutator(block).insertBeforeJumpTo(instr, movEA);
        ChunkMutator(block).insertAfter(instr, movID);
    }
    else {
        ChunkMutator(block).insertBeforeJumpTo(instr, movID);
    }
    ChunkMutator(block).insertAfter(instr, movOffset);

    delete i;
#endif
}

void UseGSTablePass::visit(DataRegion *dataRegion) {
    //TemporaryLogLevel tll("pass", 10);
    for(auto var : dataRegion->variableIterable()) {
        if(auto dest = var->getDest()) {
            if(dynamic_cast<NormalLink *>(dest)) {
                if(transformIndirectCalls) redirectFunctionPointerLinks(var);
            }
            else {
                if(dynamic_cast<TLSDataOffsetLink*>(dest)){
                }
                else if(dynamic_cast<DataOffsetLink*>(dest)){
                }
                else if(dynamic_cast<SymbolOnlyLink*>(dest)){
                }
                else if(dynamic_cast<MarkerLink*>(dest)){
                }
                else {
                    LOG(1, "what is this dest?");
                    throw "error";
                }

                LOG(10, "target address = "
                    << std::hex << dest->getTargetAddress());
                if(auto target = dest->getTarget()) {
                    LOG(10, "target is " << target->getName());
                }
            }
        }
    }
}

void UseGSTablePass::visit(PLTTrampoline *trampoline) {
    // expects CollapsePLTPass
    if(trampoline->isIFunc()) {
#if 0
        //TemporaryLogLevel tll("pass", 10);
        LOG(1, "visiting PLTTrampoline "
            << std::hex << trampoline->getAddress());
        ChunkDumper d;
        trampoline->accept(&d);
        recurse(trampoline);
        trampoline->accept(&d);
#else
        recurse(trampoline);
#endif
    }
}

void UseGSTablePass::visit(VTable *vtable) {
#if 0
    LOG(1, "converting " << vtable->getName());
    ChunkDumper d;
    vtable->accept(&d);
#endif

    recurse(vtable);
}

void UseGSTablePass::visit(VTableEntry *vtableEntry) {
#if 0
    LOG(1, "   at " << std::hex << vtableEntry->getAddress());
#endif
    auto link = vtableEntry->getLink();
    assert(dynamic_cast<AbsoluteNormalLink *>(link));

    Chunk *target = &*link->getTarget();
    if(target == nullptr) {
        LOG(1, "WARNING: unknown target for vtable entry "
            << vtableEntry->getAddress());
        return;
    }
    auto gsEntry = gsTable->makeEntryFor(target);
    vtableEntry->setLink(new GSTableLink(gsEntry));
    delete link;
}

void UseGSTablePass::redirectFunctionPointerLinks(DataVariable *var) {
    auto dest = static_cast<NormalLink *>(var->getDest());
    Chunk *target = &*dest->getTarget();
    if(target == nullptr) {
        LOG(1, "WARNING: unknown target for data variable "
            << var->getAddress());
        return;
    }

    if(dynamic_cast<DataRegion *>(target)) return;

    LOG0(10, "redirect Pointer Link "
        << std::hex << var->getAddress()
        << " org--> " << var->getDest()->getTarget()->getAddress());
    if(auto target = var->getDest()->getTarget()) {
        LOG0(10, " " << target->getName());
    }

    bool preResolve = false;
    if(auto instr = dynamic_cast<Instruction *>(target)) {
        if(auto pe = gsTable->getEntryFor(instr->getParent()->getParent())) {
            if(dynamic_cast<GSTableResolvedEntry *>(pe)) preResolve = true;
        }
    }

    auto gsEntry = gsTable->makeEntryFor(target, preResolve);
    var->setDest(new GSTableLink(gsEntry));

    LOG(10, " ==> " << gsEntry->getOffset());
    delete dest;
}

void UseGSTablePass::rewriteRIPrelativeCall(Block *block, Instruction *instr) {
    LOG(10, "rewriting RIP-relative call "
        << std::hex << instr->getAddress());
    IF_LOG(10) {
        ChunkDumper d;
        instr->accept(&d);

        auto i = static_cast<LinkedInstruction *>(instr->getSemantic());
        auto link = i->getLink();
        auto target = link->getTarget();
        LOG(1, "        target "
            << target->getName() << " "
            << std::hex << link->getTargetAddress());
    }

#ifdef ARCH_X86_64
    auto i = static_cast<LinkedInstruction *>(instr->getSemantic());
    if(!i->getLink()) return;

    DisasmHandle handle(true);

    // callq *%gs:(%r11)
    std::vector<unsigned char> bin{0x65, 0x41, 0xff, 0x13};
    auto assembly = DisassembleInstruction(handle).makeAssembly(bin);
    auto semantic = new IndirectCallInstruction(assembly, X86_REG_R11);
    instr->setSemantic(semantic);
    ChunkMutator(block).modifiedChildSize(instr,
        semantic->getSize() - i->getSize());

    // movq EA, %r11
    std::vector<unsigned char> bin2{0x4c, 0x8b, 0x1d, 0, 0, 0, 0};
    auto assembly2 = DisassembleInstruction(handle).makeAssembly(bin2);
    auto movEA = new Instruction();
    auto semantic2 = new LinkedInstruction(movEA, assembly2);
    semantic2->setLink(i->getLink());
    semantic2->setIndex(0);
    movEA->setSemantic(semantic2);

    // movq ID, %mm0
    std::vector<unsigned char> bin3{0x0f, 0x64, 0x04, 0x25, 0, 0, 0, 0};
    auto tmp = &indirectCallID;
    std::memcpy(&bin3[4], &tmp, 4);
    auto movID = DisassembleInstruction(handle).instruction(bin3);

    // movq %r11, %mm1
    std::vector<unsigned char> bin4{0x49, 0x0f, 0x6e, 0xcb};
    auto movOffset = DisassembleInstruction(handle).instruction(bin4);

    ChunkMutator(block).insertBeforeJumpTo(instr, movEA);
    ChunkMutator(block).insertAfter(instr, movID);
    ChunkMutator(block).insertAfter(instr, movOffset);

    delete i;
#endif
}

void UseGSTablePass::rewriteRIPrelativeJump(Block *block, Instruction *instr) {
    LOG(10, "    rewriting RIP-relative jump"
        << std::hex << instr->getAddress());
    IF_LOG(10) {
        ChunkDumper d;
        instr->accept(&d);
    }

    auto i = static_cast<LinkedInstruction *>(instr->getSemantic());
    if(!i->getLink()) return;

#ifdef ARCH_X86_64
    DisasmHandle handle(true);

    // jmpq %gs:(%r11)
    std::vector<unsigned char> bin{0x65, 0x41, 0xff, 0x23};
    auto assembly = DisassembleInstruction(handle).makeAssembly(bin);
    auto semantic = new IndirectCallInstruction(assembly, X86_REG_R11);
    instr->setSemantic(semantic);
    ChunkMutator(block).modifiedChildSize(instr,
        semantic->getSize() - i->getSize());

    // movq EA, %r11
    std::vector<unsigned char> bin2{0x4c, 0x8b, 0x1d, 0x34, 0, 0, 0, 0};
    auto assembly2 = DisassembleInstruction(handle).makeAssembly(bin2);
    auto movEA = new Instruction();
    auto semantic2 = new LinkedInstruction(movEA, assembly2);
    Chunk *target = &*i->getLink()->getTarget();
    auto gsEntry = gsTable->makeEntryFor(target);
    semantic2->setLink(new GSTableLink(gsEntry));
    semantic2->setIndex(0);
    movEA->setSemantic(semantic2);

    // movq ID, %mm0
    std::vector<unsigned char> bin3{0x0f, 0x64, 0x04, 0x25, 0, 0, 0, 0};
    auto tmp = &indirectCallID;
    std::memcpy(&bin3[4], &tmp, 4);
    auto movID = DisassembleInstruction(handle).instruction(bin3);

    // movq %r11, %mm1
    std::vector<unsigned char> bin4{0x49, 0x0f, 0x6e, 0xcb};
    auto movOffset = DisassembleInstruction(handle).instruction(bin4);

    ChunkMutator(block).insertBeforeJumpTo(instr, movEA);
    ChunkMutator(block).insertAfter(instr, movID);
    ChunkMutator(block).insertAfter(instr, movOffset);

    delete i;
#endif
}
