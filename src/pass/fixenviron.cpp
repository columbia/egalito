#include "fixenviron.h"
#include "elf/elfspace.h"
#include "elf/symbol.h"
#include "chunk/link.h"
#include "chunk/dataregion.h"
#include "operation/mutator.h"
#include "disasm/disassemble.h"
#include "instr/concrete.h"

#include "log/log.h"

void FixEnvironPass::visit(Program *program) {
    auto start = dynamic_cast<Function *>(program->getEntryPoint());
    if(!start) {
        LOG(1, "FixEnvironPass: can't find entry point!");
        return;
    }

    // find dynsym
    auto module = program->getFirst();
    auto dynsymlist = module->getElfSpace()->getDynamicSymbolList();

    // find data section it belongs to
    auto environ = dynsymlist->find("__environ");
    if(!environ && program->getLibc()) {
        module = program->getLibc();
        dynsymlist = module->getElfSpace()->getDynamicSymbolList();

        environ = dynsymlist->find("__environ");
    }

    if(!environ) {
        LOG(1, "FixEnvironPass: can't find __environ symbol!");
        return;
    }

    address_t environAddress = module->getBaseAddress() + environ->getAddress();
    auto section = module->getDataRegionList()->findDataSectionContaining(
        environAddress);

    if(!section) {
        LOG(1, "FixEnvironPass: can't find DataSection for __environ @"
            << std::hex << environ->getAddress());
        return;
    }

    auto offset = environAddress - section->getAddress();

#ifdef ARCH_X86_64
/* Desired code to insert into _start:
    // from __libc_start_main for static executables only:
    __environ = &argv[argc+1];  // or:
    __environ = argv + argc + 1;

    0:   4c 8d 44 f2 08          lea    0x8(%rdx,%rsi,8),%r8
    5:   4c 89 05 7b 00 00 00    mov    %r8,0x7b(%rip)

*/
    auto leaInstr = Disassemble::instruction({0x4c, 0x8d, 0x44, 0xf2, 0x08});
    static DisasmHandle handle(true);
    auto movAssembly = DisassembleInstruction(handle).makeAssemblyPtr(
        std::vector<unsigned char>({0x4c, 0x89, 0x05, 0x00, 0x00, 0x00, 0x00}));

    auto movInstr = new Instruction();
    auto movSem = new LinkedInstruction(movInstr);
    movSem->setAssembly(movAssembly);
    movSem->setLink(new DataOffsetLink(section, offset));
    movSem->setIndex(1);
    movInstr->setSemantic(movSem);

    {
        // insert after mov %rsp,%rdx in _start and use %rdx
        auto block = start->getChildren()->getIterable()->get(0);
        Instruction *insertPoint = nullptr;
        for(size_t i = 0; i < block->getChildren()->genericGetSize(); i ++) {
            auto instr = block->getChildren()->getIterable()->get(i);
            auto assembly = instr->getSemantic()->getAssembly();
            if(assembly && assembly->getId() == X86_INS_MOV) {
                auto op = assembly->getAsmOperands();
                if(op->getMode() == AssemblyOperands::MODE_REG_REG
                    && op->getOperands()[0].reg == X86_REG_RSP
                    && op->getOperands()[1].reg == X86_REG_RDX) {

                    insertPoint = instr;
                    break;
                }
            }
        }
        if(insertPoint) {
            ChunkMutator(block)
                .insertAfter(insertPoint, {leaInstr, movInstr});
        }
        else {
            LOG(0, "ERROR: FixEnvironPass: can't find mov %rsp,%rdx in _start!");
            std::exit(1);
        }
    }
    {
        ChunkMutator(start, true);
    }
    movSem->regenerateAssembly();
#else
    #error "Need FixEnvironPass for current arch!"
#endif
}
