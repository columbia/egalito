#ifndef EGALITO_GENERATE_BINGEN_H
#define EGALITO_GENERATE_BINGEN_H

#include <string>
#include <fstream>

class ElfSpace;

class BinGen {
private:
    ElfSpace *elfSpace;
    std::ofstream fs;
public:
    BinGen(ElfSpace *mainElfSpace, std::string filename)
        : elfSpace(mainElfSpace),
          fs(filename, std::ios::out | std::ios::binary) { }
    ~BinGen() { fs.close(); }
    void generate();
};

#endif
