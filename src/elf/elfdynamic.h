#ifndef EGALITO_ELF_ELFDYNAMIC_H
#define EGALITO_ELF_ELFDYNAMIC_H

#include <iosfwd>
#include <vector>
#include <string>
#include "sharedlib.h"

class ElfMap;
class LibraryList;

class ElfDynamic {
private:
    std::vector<std::string> dependencyList;
    const char *rpath;
    LibraryList *libraryList;
public:
    ElfDynamic(LibraryList *libraryList)
        : rpath(nullptr), libraryList(libraryList) {}
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
