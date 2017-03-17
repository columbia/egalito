#ifndef EGALITO_ELF_ELFGEN_H
#define EGALITO_ELF_ELFGEN_H

#include <iosfwd>
#include <vector>
#include "transform/sandbox.h"
#include "elfspace.h"
#include "elf.h"

class ElfGen {
private:
    class Section {
    private:
        std::string data;
        std::string name;
        size_t size;
        size_t fileOffset;
    public:
        Section(std::string name) : name(name), size(0) {}
        Section(std::string name, const void *data, size_t size)
            : name(name), size(0) { add(data, size); }
        size_t getSize() const { return size; }
        size_t getFileOff() const { return fileOffset; }
        std::string getName() const { return name; }
        std::string getData() const { return data; }
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
        Segment(address_t address, size_t fileOffset = 0)
            : address(address), fileOffset(fileOffset), size(0) {}
        ~Segment() { for(auto s : sections) { delete s; } }
        address_t getAddress() const { return address; }
        size_t getFileOff() const { return fileOffset; }
        size_t getSize() const { return size; }
        Elf64_Phdr* makeProgramHeader(Elf64_Word p_type, Elf64_Word p_flags, Elf64_Xword p_align) const;
        std::vector<Section *> getSections() const { return sections; }
        Section *getFirstSection() const { return sections[0]; }
        void setAddress(address_t addr) { address = addr; }
        void setFileOff(size_t offset);
        void add(Section *sec);
    };
private:
    ElfSpace *elfSpace;
    MemoryBacking *backing;
    std::string filename;
    const char *interpreter;
    std::vector<Segment *> segments;
    std::vector<Elf64_Phdr *> phdrList;
    std::vector<Elf64_Shdr *> shdrList;
private:
    Segment *headerSegment;
    Segment *shdrTableSegment;
    Segment *phdrTableSegment;
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
    void makePhdrTable();
    void makeShdrTable();
    void updateEntryPoint();
    Elf64_Sym generateSymbol(Function *func, size_t strtabIndex);
    size_t getNextFreeOffset();
    int addShdr(Section *section, Elf64_Word type, int link = 0);
    void addSegment(Segment *segment);
    void addSegment(Segment *segment, Elf64_Word p_type, Elf64_Word p_flags, Elf64_Xword p_align);
};

#endif
