#ifndef EGALITO_ELF_ELFDYNAMIC_H
#define EGALITO_ELF_ELFDYNAMIC_H

#include <iosfwd>
#include <vector>
#include <string>
#include "sharedlib.h"

class ElfMap;

class ElfDynamic {
private:
    std::vector<std::string> libraryList;
    std::vector<SharedLib *> sharedLibList;
    const char *rpath;
public:
    ElfDynamic() : rpath(nullptr) {}
    void parse(ElfMap *elf);
    void resolveLibraries();
private:
    std::vector<std::string> doGlob(std::string pattern);
    bool isValidElf(std::ifstream &file);
    void parseLdConfig(std::string filename,
        std::vector<std::string> &searchPath);
    void processLibrary(const std::string &fullPath, const std::string &filename);
};

#endif
