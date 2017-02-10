#include <set>
#include <capstone/capstone.h>
#include "piecewise.h"
#include "disassemble.h"
#include "elf/symbol.h"
#include "chunk/concrete.h"
#include "chunk/dump.h"
#include "pass/resolvecalls.h"
#include "log/log.h"

UnionFind::UnionFind(size_t count) {
    for(size_t i = 0; i < count; i ++) {
        parent.push_back(i);
    }
}

void UnionFind::join(size_t one, size_t two) {
    auto oneParent = get(one);
    auto twoParent = get(two);

    if(oneParent < twoParent) parent[twoParent] = oneParent;
    if(oneParent > twoParent) parent[oneParent] = twoParent;
}

size_t UnionFind::get(size_t where) {
    size_t i = where;
    while(parent[i] != i) {
        i = parent[i];
    }
    return i;
}

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

    soup = new BlockSoup();
    Block *block = new Block();
    block->setPosition(new AbsolutePosition(trueAddress));
    soup->setPosition(new AbsolutePosition(trueAddress));

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
            soup->getChildren()->add(block);
            block->setParent(soup);
            soup->addToSize(block->getSize());

            Block *oldBlock = block;
            block = new Block();
            block->setPosition(new SubsequentPosition(oldBlock));
        }
    }

    if(block->getSize() == 0) {
        delete block;
    }
    else {
        LOG0(1, "excess instructions at end of disassembly... "
            "adding basic block\n");
        soup->getChildren()->add(block);
        block->setParent(soup);
        soup->addToSize(block->getSize());
    }

    cs_free(insn, count);

    ResolveCalls resolveCalls;
    soup->accept(&resolveCalls);

    UnionFind unionFind(soup->getChildren()->getIterable()->getCount());
    size_t index = 0;
    size_t children = soup->getChildren()->getIterable()->getCount();
    for(auto block : soup->getChildren()->getIterable()->iterable()) {
        auto i = block->getChildren()->getIterable()->getLast();
        auto link = i->getSemantic()->getLink();
        if(auto cf = dynamic_cast<ControlFlowInstruction *>(i->getSemantic())) {
            if(cf->getMnemonic() != "jmp") {
                if(index + 1 < children) {
                    unionFind.join(index, index + 1);
                    LOG(1, "join " << std::dec << index << "," << index+1 << " because fall-through to " << std::hex << (block->getAddress() + block->getSize()));
                }
            }
            if(cf->getMnemonic() != "callq" && link) {
                auto target = soup->getChildren()->getSpatial()->findContaining(
                    link->getTargetAddress());
                if(target) {
                    size_t targetIndex = soup->getChildren()->getIterable()->indexOf(target);

                    unionFind.join(index, targetIndex);
                    LOG(1, "join " << std::dec << index << "," << targetIndex << " because jump at " << std::hex << block->getAddress());
                }
            }
        }
        else if(i->getSemantic()->getData() == "\xc3") {
            // return, don't join
        }
        else {
            if(index + 1 < children) {
                unionFind.join(index, index + 1);
                LOG(1, "join " << std::dec << index << "," << index+1 << " because normal instruction preceding " << std::hex << (block->getAddress() + block->getSize()));
            }
        }

        for(size_t i = 0; i < unionFind.getCount(); i ++) {
            if(unionFind.get(i) != i) continue;
            size_t z = 0;
            for(size_t j = 0; j < unionFind.getCount(); j ++) {
                if(unionFind.get(j) == i) z ++;
            }
            if(z < 2) continue;
            LOG0(1, "[" << std::dec << i);
            for(size_t j = 0; j < unionFind.getCount(); j ++) {
                if(i == j) continue;
                if(unionFind.get(j) == i) LOG0(1, " " << std::dec << j);
            }
            LOG0(1, "]   ");
        }
        LOG(1, "");
        index ++;
    }

    auto list = soup->getChildren()->getIterable();
    // from representative element (lowest) to total size
    std::map<size_t, size_t> rep;
    std::map<size_t, size_t> mergeCount;
    for(size_t i = 0; i < unionFind.getCount(); i ++) {
        auto parent = unionFind.get(i);
        if(i == parent) {
            rep[i] = list->get(i)->getSize();
            mergeCount[i] = 1;
        }
        else {
            auto first = list->get(parent);
            auto here = list->get(i);
            auto end = (here->getAddress() - first->getAddress())
                + here->getSize();
            if(rep[parent] < end) rep[parent] = end;

            mergeCount[parent] ++;
        }
    }

    LOG(1, "here are the piecewise functions:");
    for(auto p : rep) {
        LOG(1, std::hex << list->get(p.first)->getAddress()
            << " " << std::dec << p.second
            << " (count " << mergeCount[p.first] << ")");
    }

    ChunkDumper dumper;
    soup->accept(&dumper);
}
