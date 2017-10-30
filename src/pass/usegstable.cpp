#include "usegstable.h"
#include "chunk/concrete.h"
#include "instr/concrete.h"
#include "operation/mutator.h"
#include "disasm/disassemble.h"
#include "chunk/dump.h"
#include "log/log.h"

void UseGSTablePass::visit(Block *block) {
    auto iterable = block->getChildren()->getIterable();
    for(size_t i = 0; i < iterable->getCount(); i ++) {
        Instruction *instr = iterable->get(i);
        if(auto v = dynamic_cast<ControlFlowInstruction *>(instr->getSemantic())) {
            if(v->getMnemonic() == "callq") {
                if(transformDirectCalls) rewriteDirectCall(block, instr);
            }
            else if(auto link = v->getLink()) {
                if(dynamic_cast<ExternalNormalLink *>(link)
                    || dynamic_cast<ExternalOffsetLink *>(link)
                    || dynamic_cast<ExternalAbsoluteNormalLink *>(link)) {

                    rewriteTailRecursion(block, instr);
                }
            }
        }
        if(dynamic_cast<IndirectCallInstruction *>(instr->getSemantic())) {
            rewriteIndirectCall(block, instr);
        }
        if(auto v = dynamic_cast<IndirectJumpInstruction *>(instr->getSemantic())) {
            if(!v->isForJumpTable()) {
                rewriteIndirectTailRecursion(block, instr);
            }
        }
    }
}

void UseGSTablePass::rewriteDirectCall(Block *block, Instruction *instr) {
    auto i = static_cast<ControlFlowInstruction *>(instr->getSemantic());
    if(!i->getLink()) return;

    Chunk *target = &*i->getLink()->getTarget();
    if(target == nullptr) {
        LOG(1, "WARNING: unknown target for direct call " << instr->getName()
            << ", not transforming for gs table");
        return;
    }

    // callq  *%gs:0xdeadbeef
    DisasmHandle handle(true);
    auto assembly = DisassembleInstruction(handle).makeAssembly(
        {0x65, 0xff, 0x14, 0x25, 0, 0, 0, 0});
    auto semantic = new LinkedInstruction(instr, assembly);

    auto gsEntry = gsTable->makeEntryFor(target);
    semantic->setLink(new GSTableLink(gsEntry));
#ifdef ARCH_X86_64
    semantic->setIndex(0);  // !!!
#endif
    instr->setSemantic(semantic);

    ChunkMutator(block).modifiedChildSize(instr,
        semantic->getSize() - i->getSize());
    delete i;
#if 0
    InstrWriterGetData writer;
    semantic->accept(&writer);
    std::string s = writer.get();
    for(size_t i = 0; i < s.length(); i ++) {
        LOG0(1, ((int)s[i] & 0xff) << " ");
    }
    LOG(1, ".");
#endif
}

void UseGSTablePass::rewriteTailRecursion(Block *block, Instruction *instr) {
    ChunkDumper dumper;
    LOG0(1, "rewrite tail recursion: ");
    instr->accept(&dumper);
}

void UseGSTablePass::rewriteIndirectCall(Block *block, Instruction *instr) {
    ChunkMutator mutator(block);
}

void UseGSTablePass::rewriteIndirectTailRecursion(Block *block, Instruction *instr) {
    ChunkDumper dumper;
    LOG0(1, "rewrite indirect tail recursion in ["
        << instr->getParent()->getParent()->getName() << "]: ");
    instr->accept(&dumper);
}

#if 0
static void rewrite_indirect_call_instruction(VECTOR_TYPE(unsigned char) *buffer,
    _DInst *instruction) {

#ifdef REWRITE_FUNCTION_POINTERS
    // Note: some instructions need calls and adjusts, such as:
    /*
            ff 15 cb 38 21 00         callq  *0x2138cb(%rip)
                ->
            ff 35 cb 38 21 00         pushq  0x2138cb(%rip)
            41 5b                     pop    %r11
            65 41 ff 13               callq  *%gs:(%r11)
    */


    if (instruction->ops[0].type == O_MEM
        || instruction->ops[0].type == O_SMEM) {

        /*
              0:    ff 14 da                callq  *(%rdx,%rbx,8)
                                ->
              18:   ff 34 da                pushq  (%rdx,%rbx,8)
              1b:   41 5b                   pop    %r11
              1d:   65 41 ff 13             callq  *%gs:(%r11)
                              or ->
              18:   4c 8b 1c da             mov    (%rdx,%rbx,8),%r11
              1c:   65 41 ff 13             callq  *%gs:(%r11)
        */

        unsigned char *code = (unsigned char *)instruction->addr;
#if 0
        int transformed = 0;
        for (int i = 0; i < instruction->size; ++ i) {
            unsigned char c = code[i];
            if (i && !transformed && code[i - 1] == 0xff) {
                /* 14 -> 34 */
                c |= 0x20;
                transformed = 1;
            }
            WRITE_BYTE1(c);
        }
        WRITE_BYTE2(0x41, 0x5b);  // pop %r11
#else
        int transformed = 0;
        for (int i = 0; i < instruction->size; ++ i) {
            unsigned char c = code[i];
            if (i && !transformed && code[i - 1] == 0xff) {
                /* 14 -> 1c, use %r11 */
                c |= 0x08;
                transformed = 1;

                unsigned char rex = 0x4c;
                if(i >= 2 && code[i - 2]) {
                    rex |= code[i-2];
                }
                WRITE_BYTE2(rex, 0x8b);  // mov ...
            }
            if(transformed) WRITE_BYTE1(c);
        }
#endif

#ifdef USE_CONSTANT_INSTEAD_OF_GS
        WRITE_BYTE3(0x41, 0xff, 0x93);  // call *0xf00(%r11)
        unsigned long offset = get_gs();
        unsigned char *off_raw = (unsigned char *)&offset;
        WRITE_BYTE4(off_raw[0], off_raw[1], off_raw[2], off_raw[3]);
#elif 0
        // cause segfaults on every call
        WRITE_BYTE3(0x41, 0xff, 0xd3);  // call *%r11
#else
        // the usual instruction!
        WRITE_BYTE4(0x65, 0x41, 0xff, 0x13);  // call *%gs:(%r11)
#endif
    }
    else {
        WRITE_BYTE1(0x65);
        switch(instruction->ops[0].index) {
        case R_RAX:     WRITE_BYTE2(0xff, 0x10); break;
        case R_RBX:     WRITE_BYTE2(0xff, 0x13); break;
        case R_RCX:     WRITE_BYTE2(0xff, 0x11); break;
        case R_RDX:     WRITE_BYTE2(0xff, 0x12); break;
        case R_RSI:     WRITE_BYTE2(0xff, 0x16); break;
        case R_RDI:     WRITE_BYTE2(0xff, 0x17); break;
        case R_RSP:     WRITE_BYTE3(0xff, 0x14, 0x24); break;
        case R_RBP:     WRITE_BYTE3(0xff, 0x55, 0x00); break;
        case R_R8:      WRITE_BYTE3(0x41, 0xff, 0x10); break;
        case R_R9:      WRITE_BYTE3(0x41, 0xff, 0x11); break;
        case R_R10:     WRITE_BYTE3(0x41, 0xff, 0x12); break;
        case R_R11:     WRITE_BYTE3(0x41, 0xff, 0x13); break;
        case R_R12:     WRITE_BYTE4(0x41, 0xff, 0x14, 0x24); break;
        case R_R13:     WRITE_BYTE4(0x41, 0xff, 0x55, 0x00); break;
        case R_R14:     WRITE_BYTE3(0x41, 0xff, 0x16); break;
        case R_R15:     WRITE_BYTE3(0x41, 0xff, 0x17); break;
        default:
            LOG(FATAL, "Unknown call instruction encountered!");
            break;
        }
    }
#else
    for(size_t i = 0; i < instruction->size; i ++)
        WRITE_BYTE1(*(unsigned char *)(instruction->addr + i));
#endif
}
#endif
