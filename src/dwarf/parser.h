#ifndef EGALITO_DWARF_PARSER_H
#define EGALITO_DWARF_PARSER_H

#include <elf.h>
#include <vector>
#include <unordered_map>
#include "cursor.h"
#include "defines.h"

class CommonInformationEntry;

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

class EhFrame {
private:
    address_t map;
    Elf64_Shdr *ehSectionHeader;
    address_t ehSectionStartAddress;
    address_t ehSectionShAddr;
    address_t ehSectionEndAddress;
    uint64_t sectionOffset;
    uint64_t sizeInBytes;
    std::vector<CommonInformationEntry> cies;
    std::unordered_map<address_t, uint64_t> cieMap;
public:
    EhFrame(address_t map, address_t ehSectionHeader);
    bool getCIEIndex(address_t startAddress, uint64_t *cieIndex);
    void parseEhFrame();
};

#endif
