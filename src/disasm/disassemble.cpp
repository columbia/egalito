#include <cstdio>
#include <cstring>
#include <capstone/x86.h>
#include <capstone/arm64.h>
#include "disassemble.h"
#include "dump.h"
#include "elf/symbol.h"
#include "chunk/chunk.h"
#include "chunk/instruction.h"
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

    Function *function = new Function(symbol);
    function->setPosition(new AbsolutePosition(symbol->getAddress()));
    Block *block = new Block();
    block->setPosition(new RelativePosition(block, function->getSize()));

    for(size_t j = 0; j < count; j++) {
        auto ins = &insn[j];

        // check if this instruction ends the current basic block
        bool split = shouldSplitBlockAt(ins, handle);

        // Create Instruction from cs_insn
        auto instr = Disassemble::instruction(ins, handle, true);

        //instr->setPosition(new RelativePosition(instr, block->getSize()));
        //instr->setPosition(new SubsequentPosition(instr, block->getSize()));
        if(block->getChildren()->getIterable()->getCount() > 0) {
            instr->setPosition(new SubsequentPosition(
                block->getChildren()->getIterable()->getLast()));
        }
        else if(function->getChildren()->getIterable()->getCount() > 0) {
            instr->setPosition(new SubsequentPosition(
                function->getChildren()->getIterable()->getLast()));
        }
        else {
            instr->setPosition(new RelativePosition(instr, 0));
        }

        block->getChildren()->add(instr);
        instr->setParent(block);
        block->addToSize(instr->getSize());
        if(split) {
            function->getChildren()->add(block);
            block->setParent(function);
            function->addToSize(block->getSize());

            Block *oldBlock = block;
            block = new Block();
            //block->setPosition(new RelativePosition(block, function->getSize()));
            block->setPosition(new SubsequentPosition(oldBlock));
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

#ifdef ARCH_X86_64
    cs_x86 *x = &ins->detail->x86;
#elif defined(ARCH_AARCH64)
    cs_arm64 *x = &ins->detail->arm64;
#endif
    if(x->op_count > 0) {
        for(size_t p = 0; p < x->op_count; p ++) {
#ifdef ARCH_X86_64
            cs_x86_op *op = &x->operands[p];
            if(op->type == X86_OP_IMM) {
#elif defined(ARCH_AARCH64)
            cs_arm64_op *op = &x->operands[p];
            if(op->type == ARM64_OP_IMM) {
#endif

#ifdef ARCH_X86_64
                if(ins->id == X86_INS_CALL) {
                    unsigned long imm = op->imm;
                    auto cfi = new ControlFlowInstruction(instr,
                        std::string((char *)ins->bytes,
                        ins->size - 4),
                        ins->mnemonic,
                        4);
                    cfi->setLink(new UnresolvedLink(imm));
                    semantic = cfi;
                }
                else if(cs_insn_group(handle.raw(), ins, X86_GRP_JUMP)) {
                    // !!! should subtract op->size,
                    // !!! can't right now due to bug in capstone
                    size_t use = ins->size /* - op->size*/;
                    unsigned long imm = op->imm;
                    auto cfi = new ControlFlowInstruction(instr,
                        std::string((char *)ins->bytes, use),
                        ins->mnemonic,
                        /*op->size*/ 0);
                    cfi->setLink(new UnresolvedLink(imm));
                    semantic = cfi;
                }
#elif defined(ARCH_AARCH64)
                if(ins->id == ARM64_INS_BL) {
                    unsigned long imm = op->imm;
                    auto cfi = new ControlFlowInstruction(instr,
                        std::string((char *)ins->bytes,
                        ins->size - 4),
                        ins->mnemonic,
                        4);
                    cfi->setLink(new UnresolvedLink(imm));
                    semantic = cfi;
                }
                else if(cs_insn_group(handle.raw(), ins, ARM64_GRP_JUMP)) {
                    size_t use = ins->size /* - op->size*/;
                    unsigned long imm = op->imm;
                    auto cfi = new ControlFlowInstruction(instr,
                        std::string((char *)ins->bytes, use),
                        ins->mnemonic,
                        /*op->size*/ 0);
                    cfi->setLink(new UnresolvedLink(imm));
                    semantic = cfi;
                }
#endif
            }
#ifdef ARCH_X86_64
            else if(op->type == X86_OP_REG) {
                if(cs_insn_group(handle.raw(), ins, X86_GRP_JUMP)) {
                    semantic = new IndirectJumpInstruction(
                        *ins, op->reg, ins->mnemonic);
                }
            }
#elif defined(ARCH_AARCH64)
            else if(op->type == ARM64_OP_IMM) {
                #error "not yet implemented"
            }
#endif
        }
    }
    else {
#ifdef ARCH_X86_64
        if(ins->id == X86_INS_RET) {
            semantic = new ReturnInstruction(*ins);
        }
#elif defined(ARCH_AARCH64)
        if(ins->id == ARM64_INS_RET) {
            semantic = new ReturnInstruction(*ins);
        }
#endif
    }

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
