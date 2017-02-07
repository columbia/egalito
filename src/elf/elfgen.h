#ifndef EGALITO_ELF_ELFGEN_H
#define EGALITO_ELF_ELFGEN_H

#include <iosfwd>
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
        size_t getSize() const { return size; }
        size_t getFileOff() const { return fileOffset; }
        std::string getName() const { return name; }
        std::string getData() const { return data; }
        void setSize(size_t size) { this->size = size; }
        void setFileOff(size_t offset) { fileOffset = offset; }
        Section add(const void *data, size_t size);
        Elf64_Shdr getSectionHeader() const;
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
        Segment(address_t address, size_t fileOffset = 0)
            : address(address), fileOffset(fileOffset), size(0){}
        address_t getAddress() const { return address; }
        size_t getFileOff() const { return fileOffset; }
        size_t getSize() const { return size; }
        Elf64_Phdr getProgramHeader() const;
        std::vector<Section *> getSections() const { return sections; }
        void setAddress(address_t addr) { address = addr; }
        void setFileOff(size_t offset);
        Segment add(Section *sec);
    };
private:
    std::vector<Segment> segments;
private:
    ElfSpace *elfSpace;
    MemoryBacking *backing;
    std::string filename;
public:
    ElfGen(ElfSpace *space, MemoryBacking *backing, std::string filename)
        : elfSpace(space), backing(backing), filename(filename) {}
    friend std::ostream& operator<<(std::ostream &stream, Segment &rhs);
    friend std::ostream& operator<<(std::ostream &stream, Section &rhs);
public:
    void generate();
};

#endif
