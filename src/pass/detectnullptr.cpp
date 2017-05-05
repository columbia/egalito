#include "detectnullptr.h"
#include "instr/instr.h"
#include "instr/concrete.h"
#include "elf/symbol.h"
#include "elf/elfspace.h"
#include "operation/mutator.h"
#include "disasm/disassemble.h"
#include "log/log.h"

void DetectNullPtrPass::visit(Module *module) {
    LOG(1, "adding null pointer checks...");
    auto elfSpace = module->getElfSpace();

    auto index = elfSpace->getSymbolList()->getCount();
    failFunc = new Symbol(0x0, 0x0, "egalito_null_ptr_check_fail",
        Symbol::TYPE_FUNC, Symbol::BIND_GLOBAL, index, 0);
    elfSpace->getSymbolList()->add(failFunc, index);
    recurse(module);
}

void DetectNullPtrPass::visit(Instruction *instruction) {
    auto sem = instruction->getSemantic();
    if(dynamic_cast<IndirectJumpInstruction *>(sem)
        || dynamic_cast<IndirectCallInstruction *>(sem)) {

        LOG(1, "adding null ptr check at " << instruction->getName());
        auto block = dynamic_cast<Block *>(instruction->getParent());

        auto jumpInstr = new Instruction();
        auto jumpSemantic = new ControlFlowInstruction(X86_INS_JE,
            jumpInstr, "\x0f\x84", "je", 4);
        jumpInstr->setSemantic(jumpSemantic);
        jumpSemantic->setLink(new SymbolOnlyLink(failFunc, 0x0));

        ChunkMutator mutator(block);
        mutator.insertBeforeJumpTo(instruction, jumpInstr);
        mutator.insertBeforeJumpTo(instruction, Disassemble::instruction(
            {0x48, 0x83, 0xf8, 0x00}));
    }
}
