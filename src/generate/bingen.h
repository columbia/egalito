#ifndef EGALITO_GENERATE_BINGEN_H
#define EGALITO_GENERATE_BINGEN_H

#include <fstream>
#include <vector>
#include "types.h"

class ConductorSetup;
class Module;

class BinGen {
private:
    ConductorSetup *setup;
    Module *addon;
    std::ofstream fs;
public:
    BinGen(ConductorSetup *setup, const char *filename);
    ~BinGen();

    int generate();

private:
    address_t makeImageBox();
    void changeMapAddress(Module *module, address_t address);
    size_t getTextSize(Module *module);
    void adjustAddOnCodeAddress(address_t pos);
    void interleaveData(address_t pos);
    address_t copyInData(Module *module, address_t pos, bool writable);
    void writeOut(address_t pos);
    address_t writeOutCode(Module *module, address_t pos);
    address_t writeOutRoData(Module *module, address_t pos);
    address_t writeOutRwData(Module *module, address_t pos);
    address_t writeOutData(Module *module, address_t pos, bool writable);
};

#endif
