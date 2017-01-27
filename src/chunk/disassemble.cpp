#include <cstdio>
#include <cstring>
#include <capstone/x86.h>
#include "disassemble.h"
#include "elf/symbol.h"
#include "chunk/chunk.h"
#include "chunk/instruction.h"
#include "log/log.h"

Disassemble::Handle::Handle(bool detailed) {
    if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        throw "Can't initialize capstone handle!";
    }

    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);  // AT&T syntax
    if(detailed) {
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    }
}

Disassemble::Handle::~Handle() {
    cs_close(&handle);
}

void Disassemble::printInstruction(cs_insn *instr, const char *name,
    long offset) {

    if(name) {
        std::printf("0x%08lx:\t%s\t\t%s <%s>\n",
            instr->address, instr->mnemonic, instr->op_str, name);
    }
    else {
        std::printf("0x%08lx:\t%s\t\t%s\n",
            instr->address, instr->mnemonic, instr->op_str);
    }

#if 1
    CLOG0(10, "\t\t\t");
    for(int i = 0; i < instr->size; i ++) {
        CLOG0(10, "%02x ", (unsigned)instr->bytes[i] & 0xff);
    }
    CLOG(10, "");
#endif
}

void Disassemble::printInstructionAtOffset(cs_insn *instr, size_t offset,
    const char *name) {

    if(name) {
        std::printf("0x%08lx <+%d>:\t%s\t\t%s <%s>\n",
            instr->address, (int)offset, instr->mnemonic, instr->op_str, name);
    }
    else {
        std::printf("0x%08lx <+%d>:\t%s\t\t%s\n",
            instr->address, (int)offset, instr->mnemonic, instr->op_str);
    }
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

        IF_LOG(3) printInstruction(&insn[j], name);
    }

    cs_free(insn, count);
}

Function *Disassemble::function(Symbol *symbol, address_t baseAddr,
    SymbolList *symbolList) {

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
        auto instr = new Instruction();
        InstructionSemantic *semantic = nullptr;

        // check if this instruction ends the current basic block
        bool split = false;
        if(cs_insn_group(handle.raw(), ins, X86_GRP_JUMP)) {
            split = true;
        }
        else if(cs_insn_group(handle.raw(), ins, X86_GRP_CALL)) {
            split = true;
        }
        else if(cs_insn_group(handle.raw(), ins, X86_GRP_RET)) {
            split = true;
        }
        else if(cs_insn_group(handle.raw(), ins, X86_GRP_INT)) {
        }
        else if(cs_insn_group(handle.raw(), ins, X86_GRP_IRET)) {
        }

        cs_detail *detail = ins->detail;
        cs_x86 *x = &detail->x86;
        if(x->op_count > 0) {
            for(size_t p = 0; p < x->op_count; p ++) {
                cs_x86_op *op = &x->operands[p];
                if(op->type == X86_OP_IMM) {
                    //CLOG0(3, "    immediate operand in ");
                    //IF_LOG(3) printInstruction(ins);

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

#if 0
                        if(op->size <= ins->size) {
                            unsigned long imm = op->imm;
                            auto cfi = new ControlFlowInstruction(instr,
                                std::string((char *)ins->bytes,
                                ins->size - op->size),
                                ins->mnemonic,
                                op->size);
                            cfi->setLink(new UnresolvedLink(imm));
                            semantic = cfi;
                        }
                        else {
                            std::cout << "total size " << ins->size
                                << ", op size " << (int)op->size << std::endl;
                            printInstruction(ins, "BUG", 0);
                        }
#else
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
#endif
                    }
                }
            }
        }

        if(!semantic) {
#if 1
            semantic = new DisassembledInstruction(*ins);
#else
            if(split) {
                semantic = new DisassembledInstruction(*ins);
            }
            else {
                std::string raw;
                raw.assign(reinterpret_cast<char *>(ins->bytes), ins->size);
                semantic = new RawInstruction(raw);
            }
#endif
        }
        instr->setSemantic(semantic);
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

            block = new Block();
            block->setPosition(new RelativePosition(block, function->getSize()));
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

    cs_free(insn, count);
    return function;
}

cs_insn Disassemble::getInsn(std::string str, address_t address) {
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

void Disassemble::relocateInstruction(cs_insn *instr, address_t newAddress) {
    instr->address = newAddress;
}
