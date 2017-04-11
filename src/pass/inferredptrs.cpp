#include "inferredptrs.h"
#include "chunk/dump.h"
#include "disasm/makesemantic.h"
#include "log/log.h"

void InferredPtrsPass::visit(Module *module) {
    this->module = module;
    recurse(module);
}

void InferredPtrsPass::visit(Instruction *instruction) {
    auto semantic = instruction->getSemantic();
    if(auto v = dynamic_cast<DisassembledInstruction *>(semantic)) {
        if(v->getLink()) return;
        auto assembly = v->getAssembly();
        if(!assembly) return;

#ifdef ARCH_X86_64
        auto linked = LinkedInstruction::makeLinked(module, instruction, assembly);
        if(linked) {
            instruction->setSemantic(linked);
            delete v;
        }
#if 0
        auto asmOps = assembly->getAsmOperands();
        for(size_t i = 0; i < asmOps->getOpCount(); i ++) {
            const cs_x86_op *op = &asmOps->getOperands()[i];
            if(MakeSemantic::isRIPRelative(assembly, i)) {
                address_t target = (instruction->getAddress() + instruction->getSize()) + op->mem.disp;
                auto inferred = new LinkedInstruction(instruction, v->moveStorageFrom(), i);

                auto found = CIter::spatial(module->getFunctionList())
                    ->find(target);
                if(found) {
                    inferred->setLink(new NormalLink(found));
                    instruction->setSemantic(inferred);
                    delete v;

#if 0
                    LOG(8, "inferred function pointer at " << instruction->getAddress()
                        << " -> " << target << ":");
                    ChunkDumper d;
                    instruction->accept(&d);
#endif
                }
                else {
                    inferred->setLink(new DataOffsetLink(elf, target));
                    instruction->setSemantic(inferred);
                    delete v;
#if 0
                    LOG(8, "inferred data pointer at " << instruction->getAddress()
                        << " -> " << target << ":");
                    ChunkDumper d;
                    instruction->accept(&d);
#endif
                }
                return;
            }
            else if(op->type == X86_OP_IMM) {
                address_t target = op->imm;
                auto found = CIter::spatial(module->getFunctionList())
                    ->find(target);
                if(found) {
                    auto inferred = new AbsoluteLinkedInstruction(
                        instruction, v->moveStorageFrom(), i);
                    inferred->setLink(new ExternalNormalLink(found));
                    instruction->setSemantic(inferred);
                    delete v;
                    return;  // don't access v after we delete it
                }
                /*else {
                    inferred->setLink(new DataOffsetLink(elf, target));
                }*/
            }
        }
#endif
#elif defined(ARCH_AARCH64)
        auto linked = LinkedInstruction::makeLinked(module, instruction, assembly);
        if(linked) {
            instruction->setSemantic(linked);
            delete v;
        }
#endif
    }
}
