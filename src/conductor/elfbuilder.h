#ifndef EGALITO_CONDUCTOR_ELFBUILDER_H
#define EGALITO_CONDUCTOR_ELFBUILDER_H

#include "elf/elfspace.h"

class ElfBuilder {
private:
    ElfSpace *elfSpace;
public:
    ElfBuilder() : elfSpace(nullptr) {}
    void parseElf(ElfMap *elf);
    void parseElf(const char *filename);

    void findDependencies();
    void buildDataStructures(bool hasRelocs = true);

    ElfSpace *getElfSpace() const { return elfSpace; }
};

#endif
