#ifndef EGALITO_LOAD_SEGMAP_H
#define EGALITO_LOAD_SEGMAP_H

#include <elf.h>  // for Elf64_Phdr
#include "elf/elfmap.h"
#include "types.h"

class ConductorSetup;
class DataRegion;

class SegMap {
public:
    static void mapAllSegments(ConductorSetup *setup);
    static void mapSegments(ElfMap &elf, address_t baseAddress = 0);
private:
    static void mapElfSegment(ElfMap &elf, Elf64_Phdr *phdr, address_t baseAddress);
    static void mapRegion(DataRegion *region);
};

#endif
