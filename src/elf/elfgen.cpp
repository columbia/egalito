#include <fstream>
#include <elf.h>
#include "elfgen.h"

std::ostream& operator<<(std::ostream &stream, ElfGen::Segment &rhs) {
    stream.seekp(rhs.getFileOff());
    for(auto section : rhs.getSections()) {
        stream << section;
    }
    return stream;
}

ElfGen::Segment ElfGen::Segment::add(ElfGen::Section sec) {
    size += sec.getSize();
    sections.push_back(sec);
    return *this;
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

void ElfGen::generate() {
    // Elf Header
    Section hdr = Section(".elfheader").add(elfSpace->getElfMap()->getMap(), sizeof(Elf64_Ehdr));
    Segment hdrSegment = Segment(0, 0).add(hdr);

    // Interp
    std::string interpreter = "/lib64/ld-linux-x86-64.so.2";
    Section interp = Section(".interp").add(static_cast<const void *>(interpreter.c_str()), interpreter.length());
    auto interpSegment = Segment(0).add(interp);

    auto originalSegments = elfSpace->getElfMap()->getSegmentList();
    Elf64_Phdr *rodata;
    Elf64_Phdr *rwdata;
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

    // Read Write data
    Segment loadRWSegment(rwdata->p_vaddr, rwdata->p_offset);

    // Text
    Segment loadTextSegment(0);
    Section text = Section(".text").add((const uint8_t *)backing->getBase(), backing->getSize());
    loadTextSegment.add(text);

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

    // Program Header Table
    Section phdrTable(".phdr_table");
    Segment phdrTableSegment(sizeof(Elf64_Ehdr), sizeof(Elf64_Ehdr));
    {
        Elf64_Phdr entry; // Load RE
        entry.p_type = PT_LOAD;
        entry.p_offset = loadRESegment.getFileOff();
        entry.p_vaddr = loadRESegment.getAddress();
        entry.p_paddr = entry.p_vaddr;
        entry.p_flags = PF_R | PF_X;
        entry.p_memsz = loadRESegment.getSize();
        entry.p_filesz = loadRESegment.getSize();
        entry.p_align = rodata->p_align;
        phdrTable.add(&entry, sizeof(Elf64_Phdr));
    }
    {
        Elf64_Phdr entry; // Load RW
        entry.p_type = PT_LOAD;
        entry.p_offset = loadRWSegment.getFileOff();
        entry.p_vaddr = loadRWSegment.getAddress();
        entry.p_paddr = entry.p_vaddr;
        entry.p_flags = PF_R | PF_W;
        entry.p_memsz = loadRESegment.getSize();
        entry.p_filesz = loadRESegment.getSize();
        entry.p_align = rwdata->p_align;
        phdrTable.add(&entry, sizeof(Elf64_Phdr));
    }
    {
        Elf64_Phdr entry; // Load Text Section
        entry.p_type = PT_LOAD;
        entry.p_offset = loadRWSegment.getFileOff() + loadRWSegment.getSize();
        loadTextSegment.setFileOff(entry.p_offset);
        entry.p_vaddr = backing->getBase(); // Some really large memory address
        loadTextSegment.setAddress(entry.p_vaddr);
        entry.p_paddr = entry.p_vaddr;
        entry.p_flags = PF_R | PF_X;
        entry.p_memsz = text.getSize();
        entry.p_filesz = text.getSize();
        entry.p_align = rodata->p_align; // Rip the alignment from original elf file
        phdrTable.add(&entry, sizeof(Elf64_Phdr));
    }
    {
        Elf64_Phdr entry; // Program Table Header
        entry.p_type = PT_PHDR;
        entry.p_offset = phdrTableSegment.getFileOff();
        entry.p_vaddr = loadTextSegment.getAddress() + sizeof(Elf64_Ehdr);
        phdrTableSegment.setAddress(entry.p_vaddr);
        entry.p_paddr = entry.p_vaddr;
        entry.p_flags = PF_R | PF_X;
        entry.p_memsz = 5 * sizeof(Elf64_Phdr); // 5 is for number of segments
        entry.p_filesz = 5 * sizeof(Elf64_Phdr);
        entry.p_align = 8;
        phdrTable.add(&entry, sizeof(Elf64_Phdr));
    }
    {
        Elf64_Phdr entry; // Interp
        entry.p_type = PT_INTERP;
        entry.p_offset = 5 * sizeof(Elf64_Phdr) + phdrTableSegment.getFileOff();
        interpSegment.setFileOff(entry.p_offset);
        entry.p_vaddr = 5 * sizeof(Elf64_Phdr) + loadTextSegment.getAddress() + sizeof(Elf64_Ehdr);
        interpSegment.setAddress(entry.p_vaddr);
        entry.p_paddr = entry.p_vaddr;
        entry.p_flags = PF_R;
        entry.p_memsz = interp.getSize();
        entry.p_filesz = interp.getSize();
        entry.p_align = 1;
        phdrTable.add(&entry, sizeof(Elf64_Phdr));
    }
    phdrTableSegment.add(phdrTable);

    // Write to file
    std::ofstream fs(filename, std::ios::out | std::ios::binary);
    // First load old data that is still relevant
    fs << loadRESegment;
    fs << loadRWSegment;
    fs << hdrSegment;
    fs << phdrTableSegment;
    fs << loadTextSegment;
    fs << phdrTableSegment;
    fs.close();
}
