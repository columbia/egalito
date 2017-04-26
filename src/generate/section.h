#ifndef EGALITO_GENERATE_SECTION_H
#define EGALITO_GENERATE_SECTION_H

#include <algorithm>  // for std::find
#include <string>
#include <vector>
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
    ElfXX_Xword shdrFlags;
    Section *sectionLink;
    size_t shdrIndex;
public:
    Section(std::string name) : name(name), address(0), offset(0),
        withShdr(false), shdrType(SHT_NULL), shdrFlags(0),
        sectionLink(nullptr), shdrIndex(static_cast<size_t>(-1)) {}
    Section(std::string name, ElfXX_Word type, ElfXX_Xword flags = 0)
        : name(name), address(0), offset(0),
        withShdr(true), shdrType(type), shdrFlags(flags),
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
    virtual void commitContents() {}
public:
    friend std::ostream& operator<<(std::ostream &stream, Section &rhs);
    size_t add(const void *data, size_t size);
    size_t add(const char *data, size_t size);
    size_t add(const std::string &string, bool withNull = false);
    void addNullBytes(size_t size);
    void setShdrFlags(ElfXX_Xword flags) { shdrFlags = flags; }
    virtual ElfXX_Shdr *makeShdr(size_t index, size_t nameStrIndex);
    template<typename ElfStructType> ElfStructType *castAs()
        { return (ElfStructType *)(data.data()); }
    template<typename ElfStructType> size_t getElementCount()
        { return data.size() / sizeof(ElfStructType); }
};

/** Stores intermediate data generated from ElementType objects, which will
    be serialized into ElfContentType objects (e.g. Symbols -> ElfXX_Sym).
*/
template <typename ElementType, typename ElfContentType>
class DeferredContentSection : public Section {
private:
    typedef std::map<ElementType *, ElfContentType> ContentMapType;
    ContentMapType contentMap;

    typedef std::vector<ElementType *> ContentListType;
    ContentListType contentList;

    bool committed;
public:
    DeferredContentSection(std::string name)
        : Section(name), committed(false) {}
    DeferredContentSection(std::string name, ElfXX_Word type, ElfXX_Xword flags = 0)
        : Section(name, type, flags), committed(false) {}

    virtual size_t getElementSize() const { return sizeof(ElfContentType); }
    virtual size_t getSize() const
        { return contentList.size() * getElementSize(); }
    size_t getCount() const { return contentList.size(); }
protected:
    void addElement(ElementType *element, ElfContentType content)
        { contentMap[element] = content; contentList.push_back(element); }
    void addElementFirst(ElementType *element, ElfContentType content)
        { contentMap[element] = content; contentList.insert(contentList.begin(), element); }
    virtual void lowLevelAdd(ElfContentType &content)
        { add(static_cast<void *>(&content), sizeof(content)); }
public:
    ElfContentType &findContent(ElementType *element);
    size_t findIndex(ElementType *element);

    // returns elements in arbitrary order, not index-sorted
    ContentMapType &getContentMap() { return contentMap; }
    ContentListType &getContentList() { return contentList; }

    virtual void commitContents();
};

template <typename ElementType, typename ElfContentType>
ElfContentType &DeferredContentSection<ElementType, ElfContentType>
    ::findContent(ElementType *element) {

    return (*contentMap.find(element)).second;
}

template <typename ElementType, typename ElfContentType>
size_t DeferredContentSection<ElementType, ElfContentType>
    ::findIndex(ElementType *element) {

    auto it = std::find(contentList.begin(), contentList.end(), element);
    return (it != contentList.end()
        ? std::distance(contentList.begin(), it)
        : static_cast<size_t>(0));
}

template <typename ElementType, typename ElfContentType>
void DeferredContentSection<ElementType, ElfContentType>::commitContents() {
    if(committed) return;
    for(auto element : contentList) {
        auto &content = contentMap[element];
        lowLevelAdd(content);
    }
    committed = true;
}

// for pointer types
template <typename ElementType, typename ElfContentType>
class PtrDeferredContentSection
    : public DeferredContentSection<ElementType, ElfContentType *> {
public:
    //using DeferredContentSection::DeferredContentSection;
    PtrDeferredContentSection(std::string name)
        : DeferredContentSection<ElementType, ElfContentType *>(name) {}
    PtrDeferredContentSection(std::string name, ElfXX_Word type, ElfXX_Xword flags = 0)
        : DeferredContentSection<ElementType, ElfContentType *>(name, type, flags) {}
    virtual size_t getElementSize() const { return sizeof(ElfContentType); }
protected:
    virtual void lowLevelAdd(ElfContentType *&content)
        { this->add(static_cast<void *>(content), sizeof(*content)); }
};

#include "concretesection.h"

#endif
