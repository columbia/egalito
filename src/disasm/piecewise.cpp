#include <set>
#include <capstone/capstone.h>
#include "piecewise.h"
#include "disassemble.h"
#include "elf/symbol.h"
#include "chunk/concrete.h"
#include "chunk/dump.h"
#include "log/log.h"

void PiecewiseDisassemble::linearPass(address_t readAddress, size_t codeLength,
    address_t trueAddress) {

    Disassemble::Handle handle(true);
    cs_insn *insn;
    size_t count = cs_disasm(handle.raw(),
        (const uint8_t *)readAddress, codeLength,
        trueAddress, 0, &insn);

    // list of all points to split basic blocks at
    std::set<address_t> splitPoint;

    for(size_t j = 0; j < count; j++) {
        auto ins = &insn[j];

        if(cs_insn_group(handle.raw(), ins, X86_GRP_CALL)
            || cs_insn_group(handle.raw(), ins, X86_GRP_JUMP)) {

            cs_x86 *x = &ins->detail->x86;
            for(size_t p = 0; p < x->op_count; p ++) {
                auto op = &x->operands[p];
                if(op->type == X86_OP_IMM) {
                    splitPoint.insert(op->imm);
                }
            }
        }
    }

    Block *block = new Block();
    block->setPosition(new AbsolutePosition(trueAddress));

    for(size_t j = 0; j < count; j++) {
        auto ins = &insn[j];

        bool split = Disassemble::shouldSplitBlockAt(ins, handle);

        if(!split) {
            auto found = splitPoint.find(ins->address + ins->size);
            if(found != splitPoint.end()) split = true;
        }

        // Create Instruction from cs_insn
        auto instr = Disassemble::instruction(ins, handle, true);

        if(block->getChildren()->getIterable()->getCount() > 0) {
            instr->setPosition(new SubsequentPosition(
                block->getChildren()->getIterable()->getLast()));
        }
        else {
            block->setPosition(new AbsolutePosition(ins->address));
            instr->setPosition(new RelativePosition(instr, 0));
        }

        block->getChildren()->add(instr);
        instr->setParent(block);
        block->addToSize(instr->getSize());
        if(split) {
            blockList.push_back(block);

            Block *oldBlock = block;
            block = new Block();
            block->setPosition(new SubsequentPosition(oldBlock));
        }
    }

    blockList.push_back(block);

    if(block->getSize() == 0) {
        delete block;
    }
    else {
        LOG0(1, "excess instructions at end of disassembly... "
            "adding basic block\n");
        blockList.push_back(block);
    }

    cs_free(insn, count);

    for(auto block : blockList) {
        ChunkDumper dumper;
        block->accept(&dumper);
    }
}
