#ifndef EGALITO_GENERATE_SECTION_H
class Function;
#define EGALITO_GENERATE_SECTION_H

#include <string>
#include <vector>
#include <set>
#include <map>
#include <elf.h>
#include "elf/elfxx.h"
#include "types.h"

class Section {
private:
    std::string data;
    std::string name;
    address_t address;
    size_t offset;
    bool withShdr;
    ElfXX_Word shdrType;
    Section *sectionLink;
    size_t shdrIndex;
public:
    Section(std::string name) : name(name),
        address(0), offset(0), withShdr(false), shdrType(SHT_NULL),
        sectionLink(nullptr), shdrIndex(static_cast<size_t>(-1)) {}
    Section(std::string name, ElfXX_Word shdrType) : name(name),
        address(0), offset(0), withShdr(true), shdrType(shdrType),
        sectionLink(nullptr), shdrIndex(static_cast<size_t>(-1)) {}
    virtual ~Section() {}
    Section *with(const void *data, size_t size)
        { add(data, size); return this; }
    Section *with(const char *data, size_t size)
        { add(data, size); return this; }
public:
    std::string getData() const { return data; }
    std::string getName() const { return name; }
    address_t getAddress() const { return address; }
    size_t getOffset() const { return offset; }
    virtual size_t getSize() const { return data.size(); }
    bool hasShdr() const { return withShdr; }
    Section *getSectionLink() const { return sectionLink; }
    size_t getShdrIndex() const { return shdrIndex; }
public:
    void setAddress(address_t addr) { address = addr; }
    void setOffset(size_t off) { offset = off; }
    void setSectionLink(Section *link) { sectionLink = link; }
public:
    friend std::ostream& operator<<(std::ostream &stream, Section &rhs);
    size_t add(const void *data, size_t size);
    size_t add(const char *data, size_t size);
    size_t add(const std::string &string, bool withNull = false);
    void addNullBytes(size_t size);
    virtual ElfXX_Shdr *makeShdr(size_t index, size_t nameStrIndex);
    template<typename ElfStructType> ElfStructType *castAs()
        { return (ElfStructType *)(data.data()); }
    template<typename ElfStructType> size_t getElementCount()
        { return data.size() / sizeof(ElfStructType); }
};

class Function;
class Symbol;

class SymbolTableSection : public Section {
public:
    struct SymbolInfo {
        size_t symbolIndex;
        size_t strTabIndex;
        SymbolInfo() {}
        SymbolInfo(size_t symbolIndex, size_t strTabIndex)
            : symbolIndex(symbolIndex), strTabIndex(strTabIndex) {}
    };
private:
    size_t count;
    std::map<Symbol *, SymbolInfo> infoMap;
public:
    SymbolTableSection(std::string name, ElfXX_Word type)
        : Section(name, type), count(0) {}

    using Section::add;
    void add(Function *func, Symbol *sym, size_t nameStrIndex);

    SymbolInfo getSymbolInfo(Symbol *sym) { return infoMap[sym]; }

    virtual ElfXX_Shdr *makeShdr(size_t index, size_t nameStrIndex);
};

class RelocationSection : public Section {
private:
    Section *targetSection;
public:
    using Section::Section;

    void setTargetSection(Section *target) { targetSection = target; }

    virtual Elf64_Shdr *makeShdr(size_t index, size_t nameStrIndex);
};

class ShdrTableSection : public Section {
private:
    typedef std::vector<std::pair<ElfXX_Shdr *, Section *>> ShdrPair;
    ShdrPair shdrPairs;
public:
    using Section::Section;
    ~ShdrTableSection();
public:
    void addShdrPair(ElfXX_Shdr *shdr, Section *section) { shdrPairs.push_back(std::make_pair(shdr, section)); }
    ShdrPair getShdrPairs() { return shdrPairs; }
    virtual size_t getSize() const { return shdrPairs.size() * sizeof(ElfXX_Shdr); }
    size_t findIndex(Section *section);
public:
    friend std::ostream& operator<<(std::ostream &stream, ShdrTableSection &rhs);
};
#endif
