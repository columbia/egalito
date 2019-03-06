#include <iomanip>
#include <algorithm>
#include <capstone/x86.h>
#include "addinline.h"
#include "analysis/frametype.h"
#include "disasm/disassemble.h"
#include "instr/register.h"
#include "instr/semantic.h"
#include "instr/linked-x86_64.h"
#include "operation/mutator.h"

#include "log/log.h"
#include "log/temp.h"

std::vector<Instruction *> ChunkAddInline::getFullCode(Instruction *point) {
    auto function = dynamic_cast<Function *>(point->getParent()->getParent());
    assert(function != nullptr);

    bool redzone = !FrameType::hasStackFrame(function);
    SaveRestoreRegisters saveRestore(point, redzone);

    auto regList = modification->getClobberedRegisters();

    std::vector<Instruction *> instrList;
    extendList(instrList, saveRestore.getRegSaveCode(regList));
    extendList(instrList, modification->getNewCode());
    extendList(instrList, saveRestore.getRegRestoreCode(regList));

    return std::move(instrList);
}

void ChunkAddInline::insertBefore(Instruction *point, bool beforeJumpTo) {
    auto newCode = getFullCode(point);
    auto block = dynamic_cast<Block *>(point->getParent());
    ChunkMutator(block, true).insertBefore(point, newCode, beforeJumpTo);
}

void ChunkAddInline::insertAfter(Instruction *point) {
    auto newCode = getFullCode(point);
    auto block = dynamic_cast<Block *>(point->getParent());
    ChunkMutator(block, true).insertAfter(point, newCode);
}

ChunkAddInline::Modification *ChunkAddInline::makeModification(
    std::vector<Register> regList,
    std::function<std::vector<Instruction *> ()> generator) {

    return new ModificationImpl(regList, generator);
}

void ChunkAddInline::extendList(std::vector<Instruction *> &list,
    const std::vector<Instruction *> &additions) {
    
    std::copy(additions.begin(), additions.end(), list.end());
}

ChunkAddInline::InstrList ChunkAddInline::SaveRestoreRegisters::getRegSaveCode(
    const RegList &regList) {

    InstrList results;
    if(redzone) {
        // lea -0x80(%rsp), %rsp
        results.push_back(Disassemble::instruction({0x48, 0x8d, 0x64, 0x24, 0x80}));
    }
    for(auto reg : regList) {
        switch(reg) {
        case X86_REG_EFLAGS:
            results.push_back(Disassemble::instruction({0x9c}));  // pushfd
            break;
        case X86_REG_RAX:
            results.push_back(Disassemble::instruction({0x50}));  // push %rax
            break;
        case X86_REG_R9:
            results.push_back(Disassemble::instruction({0x41, 0x51})); // push %r9
            break;
        case X86_REG_R10:
            results.push_back(Disassemble::instruction({0x41, 0x52})); // push %r10
            break;
        case X86_REG_R11:
            results.push_back(Disassemble::instruction({0x41, 0x53})); // push %r11
            break;
        default:
            LOG(1, "saving unsupported register in ChunkAddInline");
            break;
        }
    }
    return results;
}

ChunkAddInline::InstrList ChunkAddInline::SaveRestoreRegisters::getRegRestoreCode(
    const RegList &regList) {

    InstrList results;
    for(auto reg : regList) {
        switch(reg) {
        case X86_REG_EFLAGS:
            results.push_back(Disassemble::instruction({0x9d}));  // popfd 
            break;
        case X86_REG_RAX:
            results.push_back(Disassemble::instruction({0x58}));  // pop %rax
            break;
        case X86_REG_R9:
            results.push_back(Disassemble::instruction({0x41, 0x59})); // pop %r9
            break;
        case X86_REG_R10:
            results.push_back(Disassemble::instruction({0x41, 0x5a})); // pop %r10
            break;
        case X86_REG_R11:
            results.push_back(Disassemble::instruction({0x41, 0x5b})); // pop %r11
            break;
        default:
            LOG(1, "restoring unsupported register in ChunkAddInline");
            break;
        }
    }
    if(redzone) {
        // lea 0x80(%rsp), %rsp
        results.push_back(Disassemble::instruction(
            {0x48, 0x8d, 0xa4, 0x24, 0x80, 0x00, 0x00, 0x00}));
    }
    return results;
}
