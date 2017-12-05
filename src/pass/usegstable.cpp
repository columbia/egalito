#include <cassert>
#include <cstring>
#include "usegstable.h"
#include "chunk/concrete.h"
#include "conductor/conductor.h"
#include "instr/concrete.h"
#include "operation/find2.h"
#include "operation/mutator.h"
#include "disasm/disassemble.h"
#include "chunk/dump.h"
#include "log/log.h"
#include "log/temp.h"

void UseGSTablePass::visit(Program *program) {
    redirectEgalitoFunctionPointers();
    recurse(program);
    rewriteBootArguments();
}

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
                directCalls.emplace_back(block, instr);
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
            indirectCalls.emplace_back(block, instr);
        }
        if(auto v = dynamic_cast<IndirectJumpInstruction *>(semantic)) {
            if(!v->isForJumpTable()) {
                indirectTailRecursions.emplace_back(block, instr);
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

void UseGSTablePass::redirectEgalitoFunctionPointers() {
    for(auto ifunc : CIter::children(ifuncList)) {
        auto link = ifunc->getLink();
        auto target = &*link->getTarget();
        auto gsEntry = gsTable->makeEntryFor(target);
        ifunc->setLink(new GSTableLink(gsEntry));
        delete link;
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
    // jmpq  *%gs:(%r11)
    std::vector<unsigned char> bin{0x65, 0x41, 0xff, 0x23};
    auto assembly = DisassembleInstruction(handle).makeAssembly(bin);
    auto semantic = new IndirectJumpInstruction(assembly, i->getRegister(),
        "jmpq");
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
    auto tmp = &indirectTailJumpID;
    std::memcpy(&bin3[4], &tmp, 4);
    auto movID = DisassembleInstruction(handle).instruction(bin3);

    // movq %r11, %mm1
    std::vector<unsigned char> bin4{0x49, 0x0f, 0x6e, 0xcb};
    auto movOffset = DisassembleInstruction(handle).instruction(bin4);

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
                redirectFunctionPointerLinks(var);
            }
        }
    }
}

void UseGSTablePass::visit(PLTTrampoline *trampoline) {
    // expects CollapsePLTPass
    if(trampoline->isIFunc()) {
        recurse(trampoline);
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

void UseGSTablePass::rewriteBootArguments() {
    Module *libc = nullptr;
    for(auto module : CIter::children(conductor->getProgram())) {
        if(module->getName() == "module-libc.so.6") {
            libc = module;
            break;
        }
    }
    Function *i = ChunkFind2(conductor).findFunctionInModule(
        "__libc_csu_init", conductor->getProgram()->getMain());
    Function *f = ChunkFind2(conductor).findFunctionInModule(
        "__libc_csu_fini", conductor->getProgram()->getMain());
    Function *m = ChunkFind2(conductor).findFunctionInModule(
        "main", conductor->getProgram()->getMain());
    Function *s = ChunkFind2(conductor).findFunctionInModule(
        "__libc_start_main", libc);
    assert(i);
    assert(f);
    assert(m);
    assert(s);
    auto gsEntryInit = gsTable->makeEntryFor(i);
    auto gsEntryFini = gsTable->makeEntryFor(f);
    auto gsEntryMain = gsTable->makeEntryFor(m);

    DisasmHandle handle(true);

    // mov offset of __libc_csu_init, %rcx
    std::vector<unsigned char> binI{0x48, 0xc7, 0xc1, 0, 0, 0, 0};
    uint32_t tmpI =  gsEntryInit->getOffset();
    std::memcpy(&binI[3], &tmpI, 4);
    auto movI = DisassembleInstruction(handle).instruction(binI);

    // mov offset of __libc_csu_fini, %r8
    std::vector<unsigned char> binF{0x49, 0xc7, 0xc0, 0, 0, 0, 0};
    uint32_t tmpF = gsEntryFini->getOffset();
    std::memcpy(&binF[3], &tmpF, 4);
    auto movF = DisassembleInstruction(handle).instruction(binF);

    // mov offset of main, %rdi
    std::vector<unsigned char> binM{0x48, 0xc7, 0xc7, 0, 0, 0, 0};
    uint32_t tmpM = gsEntryMain->getOffset();
    std::memcpy(&binM[3], &tmpM, 4);
    auto movM = DisassembleInstruction(handle).instruction(binM);

    auto block = s->getChildren()->getIterable()->get(0);
    auto instr = block->getChildren()->getIterable()->get(0);
    ChunkMutator mu(block);
    mu.insertBefore(instr, movI);
    mu.insertBefore(instr, movF);
    mu.insertBefore(instr, movM);
}
