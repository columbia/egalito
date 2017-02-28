#include "inferredptrs.h"
#include "chunk/dump.h"
#include "log/log.h"

void InferredPtrsPass::visit(Module *module) {
    this->module = module;
    recurse(module);
}

void InferredPtrsPass::visit(Instruction *instruction) {
    auto semantic = instruction->getSemantic();
    if(auto v = dynamic_cast<DisassembledInstruction *>(semantic)) {
        if(v->getLink()) return;
        auto ins = v->getCapstone();
        if(!ins) return;

        LOG(1, "visit inferred");
        ChunkDumper d;
        instruction->accept(&d);

#ifdef ARCH_X86_64
        cs_x86 *x = &ins->detail->x86;
        for(size_t i = 0; i < x->op_count; i ++) {
            cs_x86_op *op = &x->operands[i];
            if(op->type == X86_OP_MEM) {
                LOG(1, "    mem op ("
                    << (int)op->mem.base << ","
                    << (int)op->mem.index << ","
                    << (int)op->mem.scale << ")");
            }
            if(op->type == X86_OP_MEM
                && op->mem.base == X86_REG_RIP
                && op->mem.index == X86_REG_INVALID
                && op->mem.scale == 1) {

                LOG(1, "    IN!");
                
                address_t target = instruction->getAddress() + op->mem.disp;
                auto inferred = new InferredInstruction(*ins);
                inferred->setLink(new DataOffsetLink(target));
                instruction->setSemantic(inferred);
                delete v;
                return;
            }
        }
#endif
    }
}
