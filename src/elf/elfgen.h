#ifndef EGALITO_ELF_ELFGEN_H
#define EGALITO_ELF_ELFGEN_H
#include "elfspace.h"

class ElfGen {
private:
  ElfSpace *elfSpace;
  std::string filename;
public:
  ElfGen(ElfSpace *space, std::string filename)
    : elfSpace(space), filename(filename) {}
public:
  void generate();
};

#endif
