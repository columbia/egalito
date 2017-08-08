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
    Module *mainModule;
    Module *addon;
    std::ofstream fs;
public:
    BinGen(ConductorSetup *setup, const char *filename);
    ~BinGen();

    int generate();

private:
    void applyAdditionalTransform();
    void addCallLogging();
    void dePLT();
    address_t reassignFunctionAddress();
    address_t makeImageBox();
    void changeMapAddress(Module *module, address_t address);
    void interleaveData(address_t pos);
    address_t copyInData(Module *module, address_t pos, bool writable);
    void writeOut(address_t pos);
    address_t writeOutCode(Module *module, address_t pos);
    address_t writeOutRoData(Module *module, address_t pos);
    address_t writeOutRwData(Module *module, address_t pos);
    address_t writeOutData(Module *module, address_t pos, bool writable);
};

#endif
