#ifndef EGALITO_DISASSEMBLE_H
#define EGALITO_DISASSEMBLE_H

#include <capstone/capstone.h>
#include "types.h"

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
private:
    static void printInstruction(cs_insn *instr,
        const char *name = 0, long offset = 0);
public:
    static void debug(const uint8_t *code, size_t length,
        address_t realAddress = 0, SymbolList *symbolList = 0);

    static void function(Symbol *symbol, address_t baseAddr,
        SymbolList *symbolList = 0);
};

#endif
