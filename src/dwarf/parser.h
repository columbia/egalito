#ifndef EGALITO_DWARF_PARSER_H
#define EGALITO_DWARF_PARSER_H

#include <elf.h>
#include <vector>
#include <unordered_map>
#include "cursor.h"
#include "defines.h"

class ElfMap;

class DwarfCIE;
class DwarfFDE;

#define NUM_REGISTERS 17

typedef struct {
    int32_t type;
    uint64_t offset;
} register_data_t;

typedef struct dwarf_state_t {
    register_data_t registers[NUM_REGISTERS];
    struct dwarf_state_t *next;
    uint64_t cfaRegister;
    int64_t cfaOffset;
    address_t cfaExpression;
    size_t cfaExpressionLength;
} dwarf_state_t;

/** Parses DWARF information from a .eh_frame section. */
class DwarfParser {
private:
    std::vector<DwarfCIE> cies;
    std::unordered_map<address_t, uint64_t> cieMap;
    dwarf_state_t *rememberedState;
public:
    DwarfParser(ElfMap *elfMap);

    DwarfCIE *getCIE(size_t cieIndex);
private:
    void parse(address_t readAddress, address_t virtualAddress,
        size_t virtualSize);
    DwarfFDE *parseFDE(DwarfCursor start, size_t cieIndex,
        address_t readAddress, address_t virtualAddress);
};

#endif
