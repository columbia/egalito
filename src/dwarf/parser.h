#ifndef EGALITO_DWARF_PARSER_H
#define EGALITO_DWARF_PARSER_H

#include <vector>
#include <unordered_map>
#include "cursor.h"
#include "defines.h"

class ElfMap;

class DwarfCIE;
class DwarfFDE;
class DwarfUnwindInfo;
class DwarfState;

/** Parses DWARF information from a .eh_frame section. */
class DwarfParser {
private:
    DwarfUnwindInfo *info;
    address_t readAddress;
    address_t virtualAddress;
    DwarfState *rememberedState;
public:
    DwarfParser(ElfMap *elfMap);

    DwarfUnwindInfo *getUnwindInfo() const { return info; }
private:
    void parse(size_t virtualSize);
    DwarfState *parseInstructions(DwarfCursor start, DwarfCursor end,
        DwarfCIE *cie, uint64_t cfaIp);
    DwarfCIE *parseCIE(DwarfCursor start, DwarfCursor end, uint64_t length,
        uint64_t index);
    DwarfFDE *parseFDE(DwarfCursor start, DwarfCursor end, uint64_t length,
        size_t cieIndex);
};

#endif
