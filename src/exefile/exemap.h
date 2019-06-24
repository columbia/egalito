#ifndef EGALITO_EXEFILE_EXEMAP_H
#define EGALITO_EXEFILE_EXEMAP_H

#include <string>
#include <vector>
#include <map>
#include "types.h"
#include "util/iter.h"

/** Generic representation of a section inside an executable. Concrete
    subclasses will generally store a header, which contains the size etc.
*/
class ExeSection {
public:
    virtual ~ExeSection() {}

    virtual int getIndex() = 0;
    virtual const std::string &getName() = 0;
    virtual address_t getVirtualAddress() = 0;
    virtual char *getReadAddress() = 0;
    virtual size_t getSize() const = 0;

    virtual void setVirtualAddress(address_t address) = 0;
    virtual void setReadAddress(char *address) = 0;

    virtual bool isExecutable() const = 0;

    virtual address_t convertOffsetToVA(size_t offset) = 0;
    virtual address_t convertVAToOffset(address_t va) = 0;
};

class ExeSectionImpl : public ExeSection {
private:
    int index;
    std::string name;
    address_t virtualAddress;
    char *readAddress;
public:
    ExeSectionImpl(int index, const std::string &name);
    ExeSectionImpl(int index, const std::string &name,
        address_t virtualAddress, char *readAddress);

    virtual int getIndex() { return index; }
    virtual const std::string &getName() { return name; }
    virtual address_t getVirtualAddress() { return virtualAddress; }
    virtual char *getReadAddress() { return readAddress; }

    virtual void setVirtualAddress(address_t address) { virtualAddress = address; }
    virtual void setReadAddress(char *address) { readAddress = address; }

    virtual address_t convertOffsetToVA(size_t offset);
    virtual address_t convertVAToOffset(address_t va);
};

class ExeMap {
public:
    virtual ~ExeMap() {}

    virtual address_t getBaseAddress() const = 0;
    virtual void setBaseAddress(address_t address) = 0;

    virtual address_t getEntryPoint() const = 0;

    virtual ExeSection *findSection(const char *name) const = 0;
    virtual ExeSection *findSection(int index) const = 0;
    virtual size_t getSectionCount() const = 0;
    virtual Iterable<ExeSection *> getSectionIterable() = 0;

    template <typename T>
    T getSectionReadPtr(ExeSection *section);
    template <typename T>
    T getSectionReadPtr(int index);
    template <typename T>
    T getSectionReadPtr(const char *name);
};

template <typename T>
T ExeMap::getSectionReadPtr(ExeSection *section) {
    return reinterpret_cast<T>(section->getReadAddress());
}

template <typename T>
T ExeMap::getSectionReadPtr(int index) {
    auto section = findSection(index);
    if(!section) return static_cast<T>(0);

    return reinterpret_cast<T>(section->getReadAddress());
}

template <typename T>
T ExeMap::getSectionReadPtr(const char *name) {
    auto section = findSection(name);
    if(!section) return static_cast<T>(0);

    return getSectionReadPtr<T>(section);
}

template <typename SectionType>
class ExeMapImpl : public ExeMap {
private:
    address_t baseAddress;
    std::map<std::string, SectionType *> sectionMap;
    std::vector<SectionType *> sectionList;
public:
    virtual address_t getBaseAddress() const { return baseAddress; }
    virtual void setBaseAddress(address_t address) { baseAddress = address; }

    virtual address_t getEntryPoint() const = 0;

    virtual SectionType *findSection(const char *name) const;
    virtual SectionType *findSection(int index) const;
    virtual size_t getSectionCount() const { return sectionList.size(); }
    virtual Iterable<ExeSection *> getSectionIterable()
        { return Iterable<ExeSection *>(new STLIteratorGenerator<std::vector<SectionType *>, ExeSection *>(sectionList)); }
    const std::vector<SectionType *> &getSectionList() const
        { return sectionList; }
protected:
    void addSection(SectionType *section);
    std::map<std::string, SectionType *> &getSectionMap()
        { return sectionMap; }
};

template <typename SectionType>
SectionType *ExeMapImpl<SectionType>::findSection(const char *name) const {
    auto it = sectionMap.find(name);
    if(it == sectionMap.end()) return nullptr;

    return it->second;
}

template <typename SectionType>
SectionType *ExeMapImpl<SectionType>::findSection(int index) const {
    if(static_cast<typename std::vector<SectionType *>::size_type>(index)
        < sectionList.size()) {

        return sectionList[index];
    }
    return nullptr;
}

template <typename SectionType>
void ExeMapImpl<SectionType>::addSection(SectionType *section) {
    sectionMap[section->getName()] = section;
    auto index = static_cast<size_t>(section->getIndex());
    if(index > sectionList.size()) {
        sectionList.resize(index + 1);
        sectionList[index] = section;
    }
    else {
        sectionList.push_back(section);
    }
}

#endif
