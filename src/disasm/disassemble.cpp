#include <cstdio>
#include <cstring>
#include <capstone/x86.h>
#include <capstone/arm64.h>
#include "disassemble.h"
#include "dump.h"
#include "makesemantic.h"
#include "elf/symbol.h"
#include "chunk/chunk.h"
#include "chunk/instruction.h"
#include "chunk/mutator.h"
#include "log/log.h"

Disassemble::Handle::Handle(bool detailed) {
#ifdef ARCH_X86_64
    if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        throw "Can't initialize capstone handle!";
    }
#elif defined(ARCH_AARCH64)
    if(cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK) {
        throw "Can't initialize capstone handle!";
    }
#endif

    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);  // AT&T syntax
    if(detailed) {
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    }
}

Disassemble::Handle::~Handle() {
    cs_close(&handle);
}

void Disassemble::init() {
    PositionFactory *positionFactory = new PositionFactory(
        //PositionFactory::MODE_DEBUGGING_NO_CACHE);  // 9.30 s
        //PositionFactory::MODE_CACHED_SUBSEQUENT);   // ~6.04 s
        PositionFactory::MODE_OFFSET);              // 5.89 s
        //PositionFactory::MODE_CACHED_OFFSET);       // 6.98 s
        //PositionFactory::MODE_GENERATION_SUBSEQUENT); // ~6.25 s
    PositionFactory::setInstance(positionFactory);
}

void Disassemble::debug(const uint8_t *code, size_t length,
    address_t realAddress, SymbolList *symbolList) {

    Handle handle(symbolList != 0);
    cs_insn *insn;
    size_t count = cs_disasm(handle.raw(), code, length, realAddress, 0, &insn);
    if(count == 0) {
        CLOG(3, "# empty");
        return;
    }
    for(size_t j = 0; j < count; j++) {
        const char *name = 0;
#ifdef ARCH_X86_64
        if(symbolList && insn[j].id == X86_INS_CALL) {
            cs_x86_op *op = &insn[j].detail->x86.operands[0];
            if(op->type == X86_OP_IMM) {
                unsigned long imm = op->imm;
                auto sym = symbolList->find(imm);
                if(sym) {
                    name = sym->getName();
                }
            }
        }
#elif defined(ARCH_AARCH64)
        if(symbolList && insn[j].id == ARM64_INS_BL) {
            cs_arm64_op *op = &insn[j].detail->arm64.operands[0];
            if(op->type == ARM64_OP_IMM) {
                unsigned long imm = op->imm;
                auto sym = symbolList->find(imm);
                if(sym) {
                    name = sym->getName();
                }
            }
        }
#endif

        IF_LOG(3) DisasmDump::printInstruction(&insn[j], INT_MIN, name);
    }

    cs_free(insn, count);
}

Module *Disassemble::module(address_t baseAddr, SymbolList *symbolList) {
    Module *module = new Module();
    for(auto sym : *symbolList) {
        Function *function = Disassemble::function(sym, baseAddr);
        module->getChildren()->add(function);
        function->setParent(module);
    }
    return module;
}

Function *Disassemble::function(Symbol *symbol, address_t baseAddr) {
    address_t readAddress = baseAddr + symbol->getAddress();
    address_t trueAddress = symbol->getAddress();
    Handle handle(true);
    cs_insn *insn;
    size_t count = cs_disasm(handle.raw(),
        (const uint8_t *)readAddress, symbol->getSize(),
        trueAddress, 0, &insn);
    PositionFactory *positionFactory = PositionFactory::getInstance();

    Function *function = new Function(symbol);
    function->setPosition(
        positionFactory->makeAbsolutePosition(symbol->getAddress()));
    Block *block = new Block();
    block->setPosition(
        positionFactory->makePosition(nullptr, block, 0));

    for(size_t j = 0; j < count; j++) {
        auto ins = &insn[j];

        // check if this instruction ends the current basic block
        bool split = shouldSplitBlockAt(ins, handle);

        // Create Instruction from cs_insn
        auto instr = Disassemble::instruction(ins, handle, true);

        Chunk *prevChunk = nullptr;
        if(block->getChildren()->getIterable()->getCount() > 0) {
            prevChunk = block->getChildren()->getIterable()->getLast();
        }
        else if(function->getChildren()->getIterable()->getCount() > 0) {
            prevChunk = function->getChildren()->getIterable()->getLast();
        }
        else {
            prevChunk = nullptr;
        }
        instr->setPosition(
            positionFactory->makePosition(prevChunk, instr, block->getSize()));

        ChunkMutator(block).append(instr);
        if(split) {
            ChunkMutator(function).append(block);

            Block *oldBlock = block;
            block = new Block();
            block->setPosition(
                positionFactory->makePosition(oldBlock, block, function->getSize()));
        }
    }

    if(block->getSize() == 0) {
        delete block;
    }
    else {
        CLOG0(1, "fall-through function [%s]... "
            "adding basic block\n", symbol->getName());
        function->getChildren()->add(block);
        block->setParent(function);
        function->addToSize(block->getSize());
    }

    //cs_free(insn, count);
    return function;
}

cs_insn Disassemble::getInsn(const std::vector<unsigned char> &str, address_t address) {
    Handle handle(true);

    cs_insn *insn;
    if(cs_disasm(handle.raw(), (const uint8_t *)str.data(), str.size(),
        address, 0, &insn) != 1) {

        throw "Invalid instruction opcode string provided\n";
    }

    cs_insn ret = *insn;
    cs_free(insn, 1);
    return ret;
}

Instruction *Disassemble::instruction(
    const std::vector<unsigned char> &bytes, bool details, address_t address) {

    Handle handle(true);
    cs_insn *ins;
    if(cs_disasm(handle.raw(), (const uint8_t *)bytes.data(), bytes.size(),
        address, 0, &ins) != 1) {

        throw "Invalid instruction opcode string provided\n";
    }

    return instruction(ins, handle, details);
}

Instruction *Disassemble::instruction(cs_insn *ins, Handle &handle, bool details) {
    auto instr = new Instruction();
    InstructionSemantic *semantic = nullptr;

    semantic = MakeSemantic::makeNormalSemantic(instr, ins);

    if(!semantic) {
        if(details) {
            semantic = new DisassembledInstruction(*ins);
        }
        else {
            std::string raw;
            raw.assign(reinterpret_cast<char *>(ins->bytes), ins->size);
            semantic = new RawInstruction(raw);
        }
    }
    instr->setSemantic(semantic);

    return instr;
}

bool Disassemble::shouldSplitBlockAt(cs_insn *ins, Handle &handle) {
    bool split = false;
#ifdef ARCH_X86_64
    if(cs_insn_group(handle.raw(), ins, X86_GRP_JUMP)) {
        split = true;
    }
    else if(cs_insn_group(handle.raw(), ins, X86_GRP_CALL)) {
        split = true;
    }
    else if(cs_insn_group(handle.raw(), ins, X86_GRP_RET)) {
        split = true;
    }
    /*else if(cs_insn_group(handle.raw(), ins, X86_GRP_INT)) {
    }
    else if(cs_insn_group(handle.raw(), ins, X86_GRP_IRET)) {
    }*/
#elif defined(ARCH_AARCH64)
    if (cs_insn_group(handle.raw(), ins, ARM64_GRP_JUMP)) { //only branches
        split = true;
    }
    else if(ins->id == ARM64_INS_BL) {
        split = true;
    }
    else if(ins->id == ARM64_INS_BLR) {
        split = true;
    }
    else if(ins->id == ARM64_INS_RET) {
        split = true;
    }
    //exception generation instructions don't require split
#endif
    return split;
}
