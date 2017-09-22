#ifndef EGALITO_DWARF_PARSER_H
#define EGALITO_DWARF_PARSER_H

#include <vector>
#include <unordered_map>
#include "cursor.h"
#include "defines.h"

class ElfMap;

class DwarfCIE;
class DwarfFDE;
class DwarfState;

/** Parses DWARF information from a .eh_frame section. */
class DwarfParser {
private:
    std::vector<DwarfCIE *> cieList;
    std::vector<DwarfFDE *> fdeList;
    std::unordered_map<address_t, uint64_t> cieMap;
    DwarfState *rememberedState;
public:
    DwarfParser(ElfMap *elfMap);

    DwarfCIE *getCIE(size_t cieIndex);
private:
    void parse(address_t readAddress, address_t virtualAddress,
        size_t virtualSize);
    DwarfState *parseInstructions(DwarfCursor start, DwarfCursor end,
        DwarfCIE *cie, uint64_t cfaIp);
    DwarfCIE *parseCIE(DwarfCursor start, address_t readAddress,
        address_t virtualAddress, uint64_t length, uint64_t index);
    DwarfFDE *parseFDE(DwarfCursor start, size_t cieIndex,
        address_t readAddress, address_t virtualAddress);
};

#endif
