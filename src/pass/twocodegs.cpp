#include <cassert>
#include <cstring>
#include "twocodegs.h"
#include "chunk/concrete.h"
#include "chunk/gstable.h"
#include "chunk/link.h"
#include "conductor/conductor.h"
#include "instr/concrete.h"
#include "operation/find2.h"
#include "operation/mutator.h"
#include "disasm/disassemble.h"
#include "chunk/dump.h"
#include "log/log.h"
#include "log/temp.h"

void TwocodeGSPass::visit(Program *program) {
    redirectEgalitoFunctionPointers();
    recurse(program);
}

void TwocodeGSPass::visit(Module *module) {
    //TemporaryLogLevel tll("pass", 10, module->getName() == "module-(egalito)");
    LOG(1, "TwocodeGSPass " << module->getName());
    recurse(module);
    recurse(module->getDataRegionList());
    if(auto vtableList = module->getVTableList()) {
        recurse(vtableList);
    }
}

void TwocodeGSPass::visit(Function *function) {
    //TemporaryLogLevel tll("pass", 10, function->hasName("ngx_http_log_error"));

    recurse(function);
    convert();
    //ChunkMutator(function, true);
}

void TwocodeGSPass::visit(Block *block) {
#ifdef ARCH_X86_64
    ChunkDumper d;
    for(auto instr : CIter::children(block)) {
        IF_LOG(11) {
            instr->accept(&d);
        }
        auto semantic = instr->getSemantic();
        if(auto v = dynamic_cast<ControlFlowInstruction *>(semantic)) {
            if(v->getMnemonic() == "callq") {
                directCalls.emplace_back(block, instr);
            }
            else if(auto link = v->getLink()) {
                if(link->isExternalJump()) {
                    tailRecursions.emplace_back(block, instr);
                }
            }
        }
        else if(dynamic_cast<IndirectCallInstruction *>(semantic)) {
            indirectCalls.emplace_back(block, instr);
        }
        else if(auto v = dynamic_cast<IndirectJumpInstruction *>(semantic)) {
            if(!v->isForJumpTable()) {
                indirectTailRecursions.emplace_back(block, instr);
            }
            else {
                jumpTableJumps.emplace_back(block, instr);
            }
        }
        else if(auto v = dynamic_cast<DataLinkedControlFlowInstruction *>(semantic)) {
            if(v->isCall()) {
                RIPrelativeCalls.emplace_back(block, instr);
            }
            else {
                RIPrelativeJumps.emplace_back(block, instr);
            }
        }
        else if(dynamic_cast<ReturnInstruction *>(semantic)) {
            functionReturns.emplace_back(block, instr);
        }
        else if(auto v = dynamic_cast<LinkedInstruction *>(semantic)) {
            auto assembly = v->getAssembly();
            if(assembly->getId() == X86_INS_LEA) {
                pointerLoads.emplace_back(block, instr);
            }
            else if(auto link = v->getLink()) {
                if(dynamic_cast<NormalLink *>(link) && link->isExternalJump()) {
                    pointerLinks.emplace_back(block, instr);
                }
            }
        }
    }
#endif
}

void TwocodeGSPass::convert() {
    for(auto pair : directCalls) {
        rewriteDirectCall(pair.first, pair.second);
    }
    directCalls.clear();
    return;

    for(auto pair : tailRecursions) {
        rewriteTailRecursion(pair.first, pair.second);
    }
    tailRecursions.clear();
    for(auto pair : indirectCalls) {
        rewriteIndirectCall(pair.first, pair.second);
    }
    indirectCalls.clear();
    for(auto pair : indirectTailRecursions) {
        rewriteIndirectTailRecursion(pair.first, pair.second);
    }
    indirectTailRecursions.clear();
    for(auto pair : jumpTableJumps) {
        rewriteJumpTableJump(pair.first, pair.second);
    }
    jumpTableJumps.clear();
    for(auto pair : RIPrelativeCalls) {
        rewriteRIPrelativeCall(pair.first, pair.second);
    }
    RIPrelativeCalls.clear();
    for(auto pair : RIPrelativeJumps) {
        rewriteRIPrelativeJump(pair.first, pair.second);
    }
    RIPrelativeJumps.clear();
    for(auto pair : pointerLoads) {
        rewritePointerLoad(pair.first, pair.second);
    }
    pointerLoads.clear();
    for(auto pair : pointerLinks) {
        ChunkDumper d;
        LOG(1, "pointerLinks");
        pair.second->accept(&d);
        std::cout.flush();
        assert(0);
    }
    pointerLinks.clear();
    for(auto pair : functionReturns) {
        rewriteReturn(pair.first, pair.second);
    }
    functionReturns.clear();
}

void TwocodeGSPass::redirectEgalitoFunctionPointers() {
    for(auto ifunc : CIter::children(ifuncList)) {
        auto link = ifunc->getLink();
        auto target = &*link->getTarget();
        auto gsEntry = gsTable->makeReservedEntryFor(target);
        ifunc->setLink(new GSTableLink(gsEntry));
        delete link;
    }
}

void TwocodeGSPass::rewriteDirectCall(Block *block, Instruction *instr) {
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
    if(!dynamic_cast<Function *>(target)) return;

#ifdef ARCH_X86_64
    DisasmHandle handle(true);

    // callq *%gs:Offset
    auto semantic = new LinkedInstruction(instr);
    std::vector<unsigned char> bin{0x65, 0xff, 0x14, 0x25, 0, 0, 0, 0};
    semantic->setAssembly(DisassembleInstruction(handle).makeAssemblyPtr(bin));
    auto gsEntry = gsTable->makeReservedEntryFor(target);
    semantic->setLink(new GSTableLink(gsEntry));
    semantic->setIndex(0);
    instr->setSemantic(semantic);
    ChunkMutator(block).modifiedChildSize(instr,
        semantic->getSize() - i->getSize());

    delete i;
#endif
}

void TwocodeGSPass::rewriteTailRecursion(Block *block, Instruction *instr) {
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
    auto assembly = DisassembleInstruction(handle).makeAssemblyPtr(
        std::vector<unsigned char>{0x65, 0xff, 0x24, 0x25, 0, 0, 0, 0});
    auto semantic = new LinkedInstruction(instr);
    semantic->setAssembly(assembly);

    // assert(dynamic_cast<Function *>(target));
    auto gsEntry = gsTable->makeReservedEntryFor(target);
    semantic->setLink(new GSTableLink(gsEntry));
    semantic->setIndex(0);  // !!!
    instr->setSemantic(semantic);

    ChunkMutator(block).modifiedChildSize(instr,
        semantic->getSize() - i->getSize());

    // movd offset = 0x4(%rip), %mm1
    auto movOffset = DisassembleInstruction(handle).instruction(
        std::vector<unsigned char>({0x0f, 0x6e, 0x0d, 0x04, 0, 0, 0}));

    Instruction *jcc = nullptr;
    if(i->getMnemonic() != "jmp") {
        jcc = new Instruction();
        ControlFlowInstruction *cfi = nullptr;
        // source instruction must be 'instr', because of
        // insertBeforeJumpTo() used below
        if(i->getMnemonic() == "ja") {          // opposite: jna == jbe
            cfi = new ControlFlowInstruction(
                X86_INS_JBE, instr, "\x0f\x86", "jbe", 4);
        }
        else if(i->getMnemonic() == "jae") {    // opposite: jnae == jb
            cfi = new ControlFlowInstruction(
                X86_INS_JB, instr, "\x0f\x82", "jb", 4);
        }
        else if(i->getMnemonic() == "jb") {     // opposite: jnb == jae
            cfi = new ControlFlowInstruction(
                X86_INS_JAE, instr, "\x0f\x83", "jae", 4);
        }
        else if(i->getMnemonic() == "je") {     // opposite: jne
            cfi = new ControlFlowInstruction(
                X86_INS_JNE, instr, "\x0f\x85", "jne", 4);
        }
        else if(i->getMnemonic() == "jne") {    // opposite: je
            cfi = new ControlFlowInstruction(
                X86_INS_JE, instr, "\x0f\x84", "je", 4);
        }
        else {
            LOG(0, "WARNING: conditional jump? " << i->getMnemonic()
                << " at " << std::hex << instr->getAddress());
            assert(0);
        }
        assert(!movOffset->getNextSibling());
        auto next = block->getNextSibling();
        auto nextI = *next->getChildren()->genericIterable().begin();
        assert(nextI);
        cfi->setLink(new NormalLink(nextI, Link::SCOPE_EXTERNAL_JUMP));
        jcc->setSemantic(cfi);
    }

    if(jcc) {
        ChunkMutator(block).insertBeforeJumpTo(instr, jcc);
        ChunkMutator(block).removeLast();
        auto block2 = new Block();
        ChunkMutator(block2).append(movOffset);
        ChunkMutator(block2).append(jcc);
        ChunkMutator(block->getParent()).insertAfter(block, block2);
    }
    else {
        ChunkMutator(block).insertBeforeJumpTo(instr, movOffset);
    }

    delete i;
#endif
}

void TwocodeGSPass::rewriteIndirectCall(Block *block, Instruction *instr) {
    //TemporaryLogLevel tll("pass", 10);
    LOG0(10, "rewriteIndirectCall");
    IF_LOG(10) {
        TemporaryLogLevel tll("disasm", 10);
        ChunkDumper d;
        instr->accept(&d);
    }
#ifdef ARCH_X86_64
    DisasmHandle handle(true);
    auto i = static_cast<IndirectCallInstruction *>(instr->getSemantic());
    auto cs_reg = i->getRegister();
    assert(cs_reg != X86_REG_RIP);
    auto reg = X86Register::convertToPhysical(cs_reg);
    auto indexReg = X86Register::convertToPhysical(i->getIndexRegister());
    auto scale = i->getScale();
    int64_t displacement = i->getDisplacement();

    // jmpq *%gs:(%r11)
    std::vector<unsigned char> bin{0x65, 0x41, 0xff, 0x23};
    auto assembly = DisassembleInstruction(handle).makeAssemblyPtr(bin);
    auto semantic = new IndirectJumpInstruction(i->getRegister(), "jmp");
    semantic->setAssembly(assembly);
    instr->setSemantic(semantic);
    ChunkMutator(block).modifiedChildSize(instr,
        semantic->getSize() - i->getSize());

    // push RA1 = gs offset
    std::vector<unsigned char > pushB1{0x68, 0, 0, 0, 0};
    auto gsEntrySelf = gsTable->makeReservedEntryFor(block->getParent());
    uint32_t tmp1 = gsEntrySelf->getOffset();
    std::memcpy(&pushB1[1], &tmp1, 4);
    auto push1 = DisassembleInstruction(handle).instruction(pushB1);

    // movl instr offset, 0x4(%rsp)
    auto movRA = new Instruction();
    auto semantic2 = new LinkedInstruction(movRA);
    std::vector<unsigned char> movB{0xc7, 0x44, 0x24, 0x04, 0, 0, 0, 0};
    semantic2->setAssembly(DisassembleInstruction(handle).makeAssemblyPtr(movB));
    semantic2->setLink(new DistanceLink(block->getParent(), push1)); // instr!
    semantic2->setIndex(0);
    movRA->setSemantic(semantic2);

    // movq EA, %r11
    std::vector<unsigned char> bin2;
    if(i->hasMemoryOperand()) {
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
    auto movEA = DisassembleInstruction(handle).instruction(bin2);

    // movq %r11, %mm1
    std::vector<unsigned char> bin4{0x49, 0x0f, 0x6e, 0xcb};
    auto movOffset = DisassembleInstruction(handle).instruction(bin4);

    ChunkMutator m(block);
    //m.insertBeforeJumpTo(instr, push2);
    m.insertBeforeJumpTo(instr, push1);
    m.insertAfter(instr, movRA);
    m.insertAfter(movRA, movEA);
    m.insertAfter(movEA, movOffset);

    delete i;
#endif
}

void TwocodeGSPass::rewriteIndirectTailRecursion(Block *block,
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
    // jmpq  *%gs:(%r11)
    std::vector<unsigned char> bin{0x65, 0x41, 0xff, 0x23};
    auto assembly = DisassembleInstruction(handle).makeAssemblyPtr(bin);
    auto semantic = new IndirectJumpInstruction(i->getRegister(), "jmp");
    semantic->setAssembly(assembly);
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
        if(reg >= 8) rex |= 0b0100;
        bin2.push_back(rex);
        bin2.push_back(0x89);
        unsigned char operand = 0xc3;
        if(reg >= 8) operand |= (reg - 8) << 3;
        else         operand |= reg << 3;
        bin2.push_back(operand);
    }
    auto movEA = DisassembleInstruction(handle).instruction(bin2);

    // movq %r11, %mm1
    std::vector<unsigned char> bin4{0x49, 0x0f, 0x6e, 0xcb};
    auto movOffset = DisassembleInstruction(handle).instruction(bin4);

    if(movEA) {
        ChunkMutator(block).insertBeforeJumpTo(instr, movEA);
        ChunkMutator(block).insertAfter(instr, movOffset);
    }
    else {
        ChunkMutator(block).insertBeforeJumpTo(instr, movOffset);
    }

    delete i;
#endif
}

void TwocodeGSPass::rewriteJumpTableJump(Block *block, Instruction *instr) {
#ifdef ARCH_X86_64
    auto i = static_cast<IndirectJumpInstruction *>(instr->getSemantic());
    auto cs_reg = i->getRegister();
    auto reg = X86Register::convertToPhysical(cs_reg);

    DisasmHandle handle(true);
    // jmp %gs:(%reg)
    std::vector<unsigned char> bin{0x65};
    if(reg >= 8) {
        bin.push_back(0x41);
    }
    bin.push_back(0xff);
    if(reg >= 8) {
        if(reg == 12) {
            bin.push_back(0x24); bin.push_back(0x24);
        }
        else if(reg == 13) {
            bin.push_back(0x65); bin.push_back(0x00);
        }
        else {
            bin.push_back(0x20 + reg - 8);
        }
    }
    else {
        if(reg == 5) {
            bin.push_back(0x65); bin.push_back(0x00);
        }
        else {
            bin.push_back(0x20 + reg);
        }
    }
    auto assembly = DisassembleInstruction(handle).makeAssemblyPtr(bin);
    auto semantic = new IndirectJumpInstruction(i->getRegister(), "jmp");
    semantic->setAssembly(assembly);
    instr->setSemantic(semantic);
    ChunkMutator(block).modifiedChildSize(instr,
        semantic->getSize() - i->getSize());
    delete i;

    // movq %reg, %mm1
    std::vector<unsigned char> bin2;
    unsigned char rex = 0x48;
    if(reg >= 8) rex |= 0b0001;
    bin2.push_back(rex);
    bin2.push_back(0x0f);
    bin2.push_back(0x6e);
    unsigned char operand = 0xc8;
    if(reg >= 8) operand |= reg - 8;
    else         operand |= reg;
    bin2.push_back(operand);

    auto movOffset = DisassembleInstruction(handle).instruction(bin2);
    ChunkMutator(block).insertBeforeJumpTo(instr, movOffset);
#endif
}

void TwocodeGSPass::visit(DataRegion *dataRegion) {
    //TemporaryLogLevel tll("pass", 10);
    for(auto sec : CIter::children(dataRegion)) {
        for(auto var : CIter::children(sec)) {
            if(auto dest = var->getDest()) {
                if(dynamic_cast<NormalLink *>(dest)) {
                    redirectFunctionPointerLinks(var);
                }
            }
        }
    }
}

void TwocodeGSPass::visit(PLTTrampoline *trampoline) {
    // expects CollapsePLTPass
    if(trampoline->isIFunc()) {
        recurse(trampoline);
        convert();
        //ChunkMutator(trampoline, true);
    }
}

void TwocodeGSPass::visit(JumpTableEntry *jumpTableEntry) {
    auto link = jumpTableEntry->getLink();
    auto target = link->getTarget();
    if(target == nullptr) {
        LOG(1, "WARNING: unknown target for jump table entry "
            << jumpTableEntry->getAddress());
        return;
    }
    assert(dynamic_cast<Instruction *>(target));
    auto gsEntry = gsTable->makeReservedEntryFor(target);

    jumpTableEntry->setLink(new GSTableLink(gsEntry));
    delete link;
}

void TwocodeGSPass::visit(VTable *vtable) {
#if 0
    LOG(1, "converting " << vtable->getName());
    ChunkDumper d;
    vtable->accept(&d);
#endif

    recurse(vtable);
}

void TwocodeGSPass::visit(VTableEntry *vtableEntry) {
#if 0
    LOG(1, "   at " << std::hex << vtableEntry->getAddress());
#endif
    auto link = vtableEntry->getLink();

    Chunk *target = &*link->getTarget();
    if(target == nullptr) {
        LOG(1, "WARNING: unknown target for vtable entry "
            << vtableEntry->getAddress());
        return;
    }
    auto gsEntry = gsTable->makeReservedEntryFor(target);
    vtableEntry->setLink(new GSTableLink(gsEntry));
    delete link;
}

void TwocodeGSPass::redirectFunctionPointerLinks(DataVariable *var) {
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

    auto gsEntry = gsTable->makeReservedEntryFor(target);
    var->setDest(new GSTableLink(gsEntry));

    LOG(10, " ==> " << gsEntry->getOffset());
    delete dest;
}

void TwocodeGSPass::rewriteRIPrelativeCall(Block *block, Instruction *instr) {
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

    // jmpq *%gs:(%r11)
    std::vector<unsigned char> bin{0x65, 0x41, 0xff, 0x23};
    auto assembly = DisassembleInstruction(handle).makeAssemblyPtr(bin);
    auto semantic = new IndirectJumpInstruction(X86_REG_R11, "jmp");
    semantic->setAssembly(assembly);
    instr->setSemantic(semantic);
    ChunkMutator(block).modifiedChildSize(instr,
        semantic->getSize() - i->getSize());

    // push RA1 = gs offset
    std::vector<unsigned char > pushB1{0x68, 0, 0, 0, 0};
    auto gsEntrySelf = gsTable->makeReservedEntryFor(block->getParent());
    uint32_t tmp1 = gsEntrySelf->getOffset();
    std::memcpy(&pushB1[1], &tmp1, 4);
    auto push1 = DisassembleInstruction(handle).instruction(pushB1);

    // movl instr offset, 0x4(%rsp)
    auto movRA = new Instruction();
    auto semantic2 = new LinkedInstruction(movRA);
    std::vector<unsigned char> movB{0xc7, 0x44, 0x24, 0x04, 0, 0, 0, 0};
    semantic2->setAssembly(DisassembleInstruction(handle).makeAssemblyPtr(movB));
    semantic2->setLink(new DistanceLink(block->getParent(), push1)); // instr!
    semantic2->setIndex(0);
    movRA->setSemantic(semantic2);

    // movq EA, %r11
    std::vector<unsigned char> bin3{0x4c, 0x8b, 0x1d, 0, 0, 0, 0};
    auto assembly3 = DisassembleInstruction(handle).makeAssemblyPtr(bin3);
    auto movEA = new Instruction();
    auto semantic3 = new LinkedInstruction(movEA);
    semantic3->setAssembly(assembly3);
    semantic3->setLink(i->getLink());
    semantic3->setIndex(0);
    movEA->setSemantic(semantic3);

    // movq %r11, %mm1
    std::vector<unsigned char> bin4{0x49, 0x0f, 0x6e, 0xcb};
    auto movOffset = DisassembleInstruction(handle).instruction(bin4);

    ChunkMutator m(block);
    //m.insertBeforeJumpTo(instr, push2);
    m.insertBeforeJumpTo(instr, push1);
    m.insertAfter(instr, movRA);
    m.insertAfter(movRA, movEA);
    m.insertAfter(movEA, movOffset);

    delete i;
#endif
}

void TwocodeGSPass::rewriteRIPrelativeJump(Block *block, Instruction *instr) {
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
    auto assembly = DisassembleInstruction(handle).makeAssemblyPtr(bin);
    auto semantic = new IndirectCallInstruction(X86_REG_R11);
    semantic->setAssembly(assembly);
    instr->setSemantic(semantic);
    ChunkMutator(block).modifiedChildSize(instr,
        semantic->getSize() - i->getSize());

    // movq EA, %r11
    std::vector<unsigned char> bin2{0x4c, 0x8b, 0x1d, 0x34, 0, 0, 0, 0};
    auto assembly2 = DisassembleInstruction(handle).makeAssemblyPtr(bin2);
    auto movEA = new Instruction();
    auto semantic2 = new LinkedInstruction(movEA);
    semantic2->setAssembly(assembly2);
    if(dynamic_cast<NormalLink *>(i->getLink())) {
        Chunk *target = &*i->getLink()->getTarget();
        auto gsEntry = gsTable->makeReservedEntryFor(target);
        semantic2->setLink(new GSTableLink(gsEntry));
    }
    else {
        semantic2->setLink(i->getLink());
    }
    semantic2->setIndex(0);
    movEA->setSemantic(semantic2);

    // movq %r11, %mm1
    std::vector<unsigned char> bin4{0x49, 0x0f, 0x6e, 0xcb};
    auto movOffset = DisassembleInstruction(handle).instruction(bin4);

    ChunkMutator(block).insertBeforeJumpTo(instr, movEA);
    ChunkMutator(block).insertAfter(instr, movOffset);

    delete i;
#endif
}

void TwocodeGSPass::rewritePointerLoad(Block *block, Instruction *instr) {
#ifdef ARCH_X86_64
    auto semantic = instr->getSemantic();
    auto i = static_cast<LinkedInstruction *>(semantic);
    DisasmHandle handle(true);

    auto link = i->getLink();
    if(!dynamic_cast<NormalLink *>(link)) return;

    auto assembly = i->getAssembly();
    auto cs_reg = assembly->getAsmOperands()->getOperands()[1].reg;
    auto reg = X86Register::convertToPhysical(cs_reg);

    Chunk *target = &*link->getTarget();
    auto gsEntry = gsTable->makeReservedEntryFor(target);

    // mov $ID, %reg
    std::vector<unsigned char> bin(7);
    unsigned char rex = 0x48;
    if(reg >= 8) rex |= 0b0001;
    bin[0] = rex;
    bin[1] = 0xc7;
    unsigned char operand = 0xc0;
    if(reg >= 8) operand |= (reg - 8);
    else         operand |= reg;
    bin[2] = operand;
    uint32_t tmp = gsEntry->getOffset();
    std::memcpy(&bin[3], &tmp, 4);
    auto mov = DisassembleInstruction(handle).instructionSemantic(instr, bin);
    instr->setSemantic(mov);
    delete link;
    delete semantic;
#endif
}

void TwocodeGSPass::rewriteReturn(Block *block, Instruction *instr) {
    auto i = static_cast<ReturnInstruction *>(instr->getSemantic());
    DisasmHandle handle(true);

    // jmpq *%gs:0x8
    std::vector<unsigned char> bin{0x65, 0xff, 0x24, 0x25, 0x8, 0, 0, 0};
    auto jmpq = new IsolatedInstruction();
    auto assembly = DisassembleInstruction(handle).makeAssemblyPtr(bin);
    jmpq->setAssembly(assembly);
    instr->setSemantic(jmpq);
    ChunkMutator(block).modifiedChildSize(instr,
        jmpq->getSize() - i->getSize());
    delete i;
}
