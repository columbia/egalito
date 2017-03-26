#ifndef EGALITO_ELF_ELFGEN_H
#define EGALITO_ELF_ELFGEN_H

#include <iosfwd>
#include <vector>
#include <utility>
#include "transform/sandbox.h"
#include "util/iter.h"
#include "elfspace.h"
#include "elf.h"

class ElfGen {
private:
    class Section {
    private:
        std::string data;
        std::string name;
        address_t address;
        size_t size;
        size_t fileOffset;
    public:
        Section(std::string name)
            : name(name), address(0), size(0), fileOffset(0) {}
        Section(std::string name, const void *data, size_t size)
            : name(name), address(0), size(0), fileOffset(0) { add(data, size); }
        address_t getAddress() const { return address; }
        size_t getSize() const { return size; }
        size_t getFileOff() const { return fileOffset; }
        std::string getName() const { return name; }
        std::string getData() const { return data; }
        void setAddress(address_t addr) { address = addr; }
        void setSize(size_t sz) { size = sz; }
        void setFileOff(size_t offset) { fileOffset = offset; }
        void add(const void *data, size_t size);
        void add(const char *data, size_t size);
        Elf64_Shdr *makeSectionHeader() const;
        template<typename ElfStructType> ElfStructType *castAs()
            { return (ElfStructType *)(data.data()); }
        template<typename ElfStructType> size_t getElementCount()
            { return size / sizeof(ElfStructType); }
    };
    class Segment {
    private:
        address_t address;
        size_t fileOffset;
        size_t size;
        std::vector<Section *> sections;
    public:
        // Sometimes the first parameter will be ignored, because the Segment
        // won't be mapped into memory
        Segment() : address(0), fileOffset(0), size(0) {}
        ~Segment() { for(auto s : sections) { delete s; } }
        address_t getAddress() const { return address; }
        size_t getFileOff() const { return fileOffset; }
        size_t getSize() const { return size; }
        Elf64_Phdr* makeProgramHeader(Elf64_Word p_type, Elf64_Word p_flags, Elf64_Xword p_align) const;
        std::vector<Section *> getSections() const { return sections; }
        Section *getFirstSection() const { return sections[0]; }
        void setAddress(address_t addr);
        void setFileOff(size_t offset);
        void add(Section *sec);
    };
private:
    class Metadata {
    private:
        typedef std::vector<Segment *> SegmentList;
        typedef std::vector<Elf64_Phdr *> PhdrList;
        typedef std::vector<std::pair<Section *, Elf64_Shdr *>> ShdrList;
    private:
        SegmentList segmentList;
        PhdrList phdrList;
        ShdrList shdrList;
    public:
        ConcreteIterable<SegmentList> getSegmentList() { return ConcreteIterable<SegmentList>(segmentList); }
        ConcreteIterable<PhdrList> getPhdrList() { return ConcreteIterable<PhdrList>(phdrList); }
        ConcreteIterable<ShdrList> getShdrList() { return ConcreteIterable<ShdrList>(shdrList); }
        std::pair<Section *, Elf64_Shdr *> getLastShdr() { return shdrList.back(); }
        void addSegment(Segment *segment) { segmentList.push_back(segment); }
        void addPhdr(Elf64_Phdr *phdr) { phdrList.push_back(phdr); }
        void addShdr(Section *section, Elf64_Shdr *shdr) { shdrList.push_back(std::make_pair(section, shdr)); }
        size_t getSegmentListSize() const { return segmentList.size(); }
        size_t getPhdrListSize() const { return phdrList.size(); }
        size_t getShdrListSize() const { return shdrList.size(); }
    public:
        ~Metadata();
    };
private:
    ElfSpace *elfSpace;
    MemoryBacking *backing;
    std::string filename;
    const char *interpreter;
    Metadata data;
private:
    Section *shdrTable;
    // Placed in the order they show up in the file
    Segment *headerSegment;
    Segment *visibleSegment;
    Segment *phdrTableSegment;
    Segment *hiddenSegment;
public:
    ElfGen(ElfSpace *space, MemoryBacking *backing, std::string filename,
        const char *interpreter = nullptr);
    friend std::ostream& operator<<(std::ostream &stream, Segment &rhs);
    friend std::ostream& operator<<(std::ostream &stream, Section &rhs);
public:
    void generate();
private:
    void makeOriginalSegments();
    void makeNewTextSegment();
    void makeSymbolInfo();
    void makeDynamicSymbolInfo();
    void makePLT();
    void makeDynamic();
    void makePhdrTable();
    void makeShdrTable();
    void updateEntryPoint();
    Elf64_Sym generateSymbol(Function *func, Symbol *sym, size_t strtabIndex);
    size_t getNextFreeOffset();
    address_t getNextFreeAddress(Segment *segment);
    int addShdr(Section *section, Elf64_Word type, int link = 0);
    void addSegment(Segment *segment);
    void addSegment(Segment *segment, Elf64_Word p_type, Elf64_Word p_flags, Elf64_Xword p_align);
};

#endif
