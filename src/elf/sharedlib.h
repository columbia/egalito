#ifndef EGALITO_ELF_SHAREDLIB_H
#define EGALITO_ELF_SHAREDLIB_H

#include <vector>
#include <map>
#include <string>

class ElfMap;

class SharedLib {
private:
    std::string fullPath;
    std::string filename;
    ElfMap *elfMap;
public:
    SharedLib(const std::string &fullPath, const std::string &filename, ElfMap *elfMap)
        : fullPath(fullPath), filename(filename), elfMap(elfMap) {}

    std::string getFullPath() const { return fullPath; }
    std::string getShortName() const { return filename; }
    ElfMap *getElfMap() const { return elfMap; }
};

class LibraryList {
private:
    std::vector<SharedLib *> libraryList;
    std::map<std::string, SharedLib *> libraryMap;
public:
    bool contains(const std::string &fullPath) const
        { return libraryMap.find(fullPath) != libraryMap.end(); }

    void add(SharedLib *library);

    size_t getCount() const { return libraryList.size(); }
    SharedLib *get(size_t i) { return libraryList[i]; }
};

#endif
