#ifndef EGALITO_DISASSEMBLE_H
#define EGALITO_DISASSEMBLE_H

#include <capstone/capstone.h>
#include "types.h"
#include "chunk/chunk.h"
#include "chunk/concrete.h"

class Symbol;
class SymbolList;

class Disassemble {
private:
    class Handle {
    private:
        csh handle;
    public:
        Handle(bool detailed = false);
        ~Handle();

        csh &raw() { return handle; }
    };
public:
    static void printInstruction(cs_insn *instr,
        const char *name = 0, long offset = 0);
    static void printInstructionAtOffset(cs_insn *instr,
        size_t offset, const char *name = 0);
public:
    static void debug(const uint8_t *code, size_t length,
        address_t realAddress = 0, SymbolList *symbolList = 0);

    static Function *function(Symbol *symbol, address_t baseAddr,
        SymbolList *symbolList = 0);
    static cs_insn getInsn(std::string str, address_t address = 0);

    static void relocateInstruction(cs_insn *instr, address_t newAddress);
};

#endif
