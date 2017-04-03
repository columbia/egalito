#include "dumptlsinstr.h"
#include "chunk/concrete.h"
#include "chunk/dump.h"
#include "log/log.h"

void DumpTLSInstrPass::visit(Instruction *instruction) {
    auto semantic = instruction->getSemantic();
    auto v = dynamic_cast<DisassembledInstruction *>(semantic);
    if(!v) return;
    auto assembly = v->getAssembly();
    if(!assembly) return;

#ifdef ARCH_X86_64
    auto asmOps = assembly->getAsmOperands();
    for(size_t i = 0; i < asmOps->getOpCount(); i ++) {
        const cs_x86_op *op = &asmOps->getOperands()[i];
        if((op->type == X86_OP_REG && op->reg == X86_REG_FS)
            || (op->type == X86_OP_MEM && op->mem.segment == X86_REG_FS)) {

            LOG(1, "TLS (fs) instruction " << instruction->getName()
                << " inside "
                << instruction->getParent()->getParent()->getName());
            ChunkDumper dumper;
            instruction->accept(&dumper);
            break;
        }
    }
#endif
}
