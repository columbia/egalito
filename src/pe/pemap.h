#ifndef EGALITO_PE_PEMAP_H
#define EGALITO_PE_PEMAP_H

#ifdef USE_WIN64_PE

#include <vector>
#include <string>
#include "types.h"

#include "parser-library/parse.h"

class PEMap {
private:
    peparse::parsed_pe *peRef;
private:
    const char *shstrtab;
    const char *strtab;
    const char *dynstr;
    //std::map<std::string, ElfSection *> sectionMap;
    //std::vector<ElfSection *> sectionList;
    //std::vector<void *> segmentList;
    const char *interpreter;
private:
    address_t baseAddress;
    address_t copyBase;
    address_t rwCopyBase;
public:
    PEMap(const std::string &filename);
    ~PEMap();
    static bool isPE(const std::string &filename);
private:
    void throwError(const std::string &err);
    void setup();
    void parsePE(const std::string &filename);
    void verifyPE();
    //void makeSectionMap();
    //void makeSegmentList();
    //void makeVirtualAddresses();
public:
    void setBaseAddress(address_t base) { baseAddress = base; }
    address_t getBaseAddress() const { return baseAddress; }
    address_t getCopyBaseAddress() const { return copyBase; }
    address_t getRWCopyBaseAddress() const { return rwCopyBase; }
    /*size_t getLength() const { return length; }
    const char *getStrtab() const { return strtab; }
    const char *getDynstrtab() const { return dynstr; }
    const char *getSHStrtab() const { return shstrtab; }

    ElfSection *findSection(const char *name) const;
    ElfSection *findSection(int index) const;
    template <typename T>
    T getSectionReadPtr(ElfSection *section);
    template <typename T>
    T getSectionReadPtr(int index);
    template <typename T>
    T getSectionReadPtr(const char *name);

    std::vector<void *> findSectionsByType(int type) const;
    std::vector<void *> findSectionsByFlag(long flag) const;

    bool hasInterpreter() const { return interpreter != nullptr; }
    const char *getInterpreter() const { return interpreter; }

    size_t getEntryPoint() const;
    bool isExecutable() const;
    bool isSharedLibrary() const;
    bool isObjectFile() const;
    bool isDynamic() const;
    bool hasRelocations() const;

    char *getCharmap() { return static_cast<char *>(map); }
    void *getMap() { return map; }
    int getFileDescriptor() const { return fd; }
    const std::vector<void *> &getSegmentList() const
        { return segmentList; }
    const std::vector<ElfSection *> &getSectionList() const
        { return sectionList; }*/
};

#if 0
template <typename T>
T PEMap::getSectionReadPtr(ElfSection *section) {
    return reinterpret_cast<T>(section->getReadAddress());
}

template <typename T>
T PEMap::getSectionReadPtr(int index) {
    ElfSection *section = findSection(index);
    if (!section) return static_cast<T>(0);

    return reinterpret_cast<T>(section->getReadAddress());
}

template <typename T>
T PEMap::getSectionReadPtr(const char *name) {
    auto section = findSection(name);
    if (!section) return static_cast<T>(0);

    return getSectionReadPtr<T>(section);
}
#endif

#endif  // USE_WIN64_PE
#endif
