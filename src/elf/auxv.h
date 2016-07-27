#ifndef EGALITO_ELF_AUXV_H
#define EGALITO_ELF_AUXV_H

#include "types.h"
#include "elf/elfmap.h"

void adjustAuxiliaryVector(char **argv, ElfMap *elf, ElfMap *interpreter);

#endif
