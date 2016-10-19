#include <cstring>
#include <fstream>
#include <elf.h>
#include "elfgen.h"
#include "log/registry.h"
#include "log/log.h"

std::ostream& operator<<(std::ostream &stream, ElfGen::Segment &rhs) {
    stream.seekp(rhs.getFileOff());
    for(auto section : rhs.getSections()) {
        stream << *section;
    }
    return stream;
}

ElfGen::Segment ElfGen::Segment::add(ElfGen::Section *sec) {
    size += sec->getSize();
    sections.push_back(sec);
    return *this;
}

Elf64_Phdr ElfGen::Segment::getProgramHeader() const {
    Elf64_Phdr entry;
    entry.p_offset = fileOffset;
    entry.p_vaddr = address;
    entry.p_paddr = entry.p_vaddr;
    entry.p_memsz = size;
    entry.p_filesz = size;
    return entry;
}

std::ostream& operator<<(std::ostream &stream, ElfGen::Section &rhs) {
    stream << rhs.getData();
    return stream;
}

ElfGen::Section ElfGen::Section::add(const void *data, size_t size) {
    this->data.append(static_cast<const char *>(data), size);
    this->size += size;
    return *this;
}

Elf64_Shdr ElfGen::Section::getSectionHeader() const {
    // So compiler doesn't complain
    Elf64_Shdr entry;
    return entry;
}

void ElfGen::generate() {
    // Elf Header
    Section hdr = Section(".elfheader").add(elfSpace->getElfMap()->getMap(), sizeof(Elf64_Ehdr));
    Elf64_Ehdr *header = hdr.castAs<Elf64_Ehdr>();
    Segment hdrSegment = Segment(0, 0).add(&hdr);

    // Interp
    std::string interpreter = "/lib64/ld-linux-x86-64.so.2";
    Section interp = Section(".interp").add(static_cast<const void *>(interpreter.c_str()), interpreter.length());
    auto interpSegment = Segment(0).add(&interp);

    auto originalSegments = elfSpace->getElfMap()->getSegmentList();
    Elf64_Phdr *rodata = nullptr;
    Elf64_Phdr *rwdata = nullptr;
    for(auto original : originalSegments) {
        Elf64_Phdr *segment = static_cast<Elf64_Phdr *>(original);
        if(segment->p_type == PT_LOAD && segment->p_flags == (PF_R | PF_X)) {
            rodata = segment;
        }
        if(segment->p_type == PT_LOAD && segment->p_flags == (PF_R | PF_W)) {
            rwdata = segment;
        }
    }
    // Rodata
    Segment loadRESegment(rodata->p_vaddr, rodata->p_offset);
    Section loadRE = Section(".old_re").add(elfSpace->getElfMap()->getMap(), rodata->p_memsz);
    loadRESegment.add(&loadRE);

    // Read Write data
    Segment loadRWSegment(rwdata->p_vaddr, rwdata->p_offset);
    char *loadRWVirtualAdress = static_cast<char *>(elfSpace->getElfMap()->getMap()) + loadRESegment.getFileOff();
    Section loadRW = Section(".old_rw").add(static_cast<void *>(loadRWVirtualAdress), rwdata->p_memsz);
    loadRWSegment.add(&loadRW);

    // Text
    Segment loadTextSegment(backing->getBase(), loadRWSegment.getFileOff() + loadRWSegment.getSize());

    Section text = Section(".text").add((const uint8_t *)backing->getBase(), backing->getSize());
    loadTextSegment.add(&text);
    interpSegment.setFileOff(loadTextSegment.getFileOff() + loadTextSegment.getSize());

    // Symbol Table
    // Section symtabSection(".symtab");
    // for(auto chunk : elfSpace->getChunkList()) {
    //     Elf64_Sym symbol;
    //     symbol.st_name = chunk.getName();
    //     symbol.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    //     symbol.st_shndx = getSectionIndex();
    //     symbol.st_addr = chunk.getAddress(); // This should change
    //     symbol.st_size = chunk.getSize();
    //     symtabSection.add(symbol, sizeof(Elf64_Sym));
    // }
    address_t entry_pt = 0;
    ChunkList<Function> *chunkList = elfSpace->getChunkList();
    for(auto chunk : *chunkList) {
        if(!strcmp(chunk->getName().c_str(), "_start"))
            entry_pt = chunk->getAddress();
    }

    // Program Header Table
    Section phdrTable(".phdr_table");
    Segment phdrTableSegment(loadRESegment.getAddress() + loadRESegment.getSize(), sizeof(Elf64_Ehdr));
    {
        Elf64_Phdr entry = phdrTableSegment.getProgramHeader(); // Program Table Header
        entry.p_type = PT_PHDR;
        entry.p_flags = PF_R | PF_X;
        entry.p_memsz = 5 * sizeof(Elf64_Phdr); // 5 is for number of segments
        entry.p_filesz = 5 * sizeof(Elf64_Phdr);
        entry.p_align = 8;
        phdrTable.add(&entry, sizeof(Elf64_Phdr));
        interpSegment.setAddress(phdrTableSegment.getAddress() + entry.p_memsz);
    }
    {
        Elf64_Phdr entry = loadRESegment.getProgramHeader();
        entry.p_type = PT_LOAD;
        entry.p_flags = PF_R | PF_X;
        entry.p_align = rodata->p_align;
        phdrTable.add(&entry, sizeof(Elf64_Phdr));
    }
    {
        Elf64_Phdr entry = loadRWSegment.getProgramHeader();
        entry.p_type = PT_LOAD;
        entry.p_flags = PF_R | PF_W;
        entry.p_align = rwdata->p_align;
        phdrTable.add(&entry, sizeof(Elf64_Phdr));
    }
    {
        Elf64_Phdr entry = loadTextSegment.getProgramHeader();
        entry.p_type = PT_LOAD;
        entry.p_flags = PF_R | PF_X;
        entry.p_align = rodata->p_align; // Rip the alignment from original elf file
        phdrTable.add(&entry, sizeof(Elf64_Phdr));
    }
    {
        Elf64_Phdr entry = interpSegment.getProgramHeader();
        entry.p_type = PT_INTERP;
        entry.p_flags = PF_R;
        entry.p_align = 1;
        phdrTable.add(&entry, sizeof(Elf64_Phdr));
    }
    phdrTableSegment.add(&phdrTable);
    header->e_entry = entry_pt;
    header->e_phoff = phdrTableSegment.getFileOff();
    header->e_phnum = phdrTable.getSize() / sizeof(Elf64_Phdr);
    header->e_shoff = 0;
    header->e_shnum = 0;
    header->e_shstrndx = SHN_UNDEF;

    // Write to file
    std::ofstream fs(filename, std::ios::out | std::ios::binary);
    // First load old data that is still relevant
    fs << loadRESegment;
    fs << loadRWSegment;
    fs << hdrSegment;
    fs << phdrTableSegment;
    fs << loadTextSegment;
    fs << interpSegment;
    fs.close();
}
