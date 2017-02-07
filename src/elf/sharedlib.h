#ifndef EGALITO_ELF_SHAREDLIB_H
#define EGALITO_ELF_SHAREDLIB_H

class ElfMap;

class SharedLib {
private:
    std::string fullPath;
    std::string filename;
public:
    SharedLib(const std::string &fullPath, const std::string &filename)
        : fullPath(fullPath), filename(filename) {}
};

class LibraryList {
private:
    std::vector<SharedLib *> libraryList;
public:
    void add(SharedLib *library) { libraryList.push_back(library); }
};

#endif
