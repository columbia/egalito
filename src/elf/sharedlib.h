#ifndef EGALITO_ELF_SHAREDLIB_H
#define EGALITO_ELF_SHAREDLIB_H

#include <vector>
#include <map>
#include <string>

class ElfMap;
class ElfSpace;

class SharedLib {
private:
    std::string fullPath;
    std::string filename;
    ElfMap *elfMap;
    ElfSpace *elfSpace;
public:
    SharedLib(const std::string &fullPath, const std::string &filename, ElfMap *elfMap)
        : fullPath(fullPath), filename(filename), elfMap(elfMap), elfSpace(nullptr) {}

    std::string getAlternativeSymbolFile() const;

    std::string getFullPath() const { return fullPath; }
    std::string getShortName() const { return filename; }
    ElfMap *getElfMap() const { return elfMap; }
    ElfSpace *getElfSpace() const { return elfSpace; }
    void setElfSpace(ElfSpace *space) { elfSpace = space; }
};

class LibraryList {
protected:
    typedef std::vector<SharedLib *> LibraryListType;
private:
    LibraryListType libraryList;
    std::map<std::string, SharedLib *> libraryMap;
public:
    bool contains(const std::string &fullPath) const
        { return libraryMap.find(fullPath) != libraryMap.end(); }

    void add(SharedLib *library);

    size_t getCount() const { return libraryList.size(); }
    SharedLib *get(size_t i) { return libraryList[i]; }
    SharedLib *get(const std::string &name);
    SharedLib *getLibc();  // for testing

    LibraryListType::const_iterator begin() const { return libraryList.begin(); }
    LibraryListType::const_iterator end() const { return libraryList.end(); }
};

#endif
