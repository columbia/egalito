#ifndef EGALITO_ELF_AUXV_H
#define EGALITO_ELF_AUXV_H

#include "types.h"
#include "elf/elfmap.h"

bool invokedAsImplicitLoader(char **argv, ElfMap *elf);
void adjustAuxiliaryVector(char **argv, ElfMap *elf, ElfMap *interpreter);
int removeLoaderFromArgv(void *argv);

#endif
