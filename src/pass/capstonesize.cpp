#include "pass/capstonesize.h"

void CapstoneSizePass::visit(Instruction *instruction) {
    if(auto cs = instruction->getSemantic()->getCapstone()) {
        accumulate(static_cast<size_t>(cs->size));
    }
}

void CapstoneSizePass::accumulate(size_t size) {
    count++;
    cs_size += sizeof(cs_insn) + sizeof(cs_detail);
    raw_size += size;
}

