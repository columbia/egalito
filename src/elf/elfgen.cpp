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
    sec->setFileOff(fileOffset + size);
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

void ElfGen::Segment::setFileOff(size_t offset) {
    long int diff = offset - fileOffset;
    for(auto sec : sections) {
        sec->setFileOff(sec->getFileOff() + diff);
    }
    fileOffset = offset;
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
    Elf64_Shdr entry;
    entry.sh_offset = fileOffset;
    entry.sh_size = size;
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
    size_t newLoadOffset = loadRWSegment.getFileOff() + loadRWSegment.getSize();
    newLoadOffset += 0xfff - ((newLoadOffset + 0xfff) & 0xfff);
    Segment loadTextSegment(backing->getBase(), newLoadOffset);
    Section text = Section(".text").add((const uint8_t *)backing->getBase(), backing->getSize());
    loadTextSegment.add(&text);
    loadTextSegment.add(&interp);

    // Symbol Table
    Segment debugSegment(0, loadTextSegment.getFileOff() + loadTextSegment.getSize());
    Section strtab(".strtab");
    std::vector<char> strtabData = {'\0'};
    Section symtab(".symtab");
    auto chunkList = elfSpace->getModule()->getChildren();
    size_t strtabIndex = 1;
    for(auto chunk : chunkList->genericIterable()) {
        auto name = chunk->getName();
        strtabData.insert(strtabData.end(), name.begin(), name.end());
        strtabData.push_back('\0');
        Elf64_Sym symbol;
        symbol.st_name = strtabIndex;
        symbol.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
        symbol.st_shndx = 1; // getSectionIndex();
        symbol.st_value = chunk->getAddress();
        symbol.st_size = chunk->getSize();
        symtab.add(static_cast<void *>(&symbol), sizeof(Elf64_Sym));
        strtabIndex += chunk->getName().length() + 1;
    }

    strtab.add(static_cast<const void *>(strtabData.data()), strtabIndex);
    debugSegment.add(&symtab);
    debugSegment.add(&strtab);

    // Program Header Table
    Section phdrTable(".phdr_table");
    Segment phdrTableSegment(loadRESegment.getAddress() + loadRESegment.getSize(), sizeof(Elf64_Ehdr));
    {
        Elf64_Phdr entry = phdrTableSegment.getProgramHeader(); // Program Table Header
        entry.p_type = PT_PHDR;
        entry.p_flags = PF_R | PF_X;
        entry.p_memsz = 4 * sizeof(Elf64_Phdr); // 4 is for number of segments
        entry.p_filesz = entry.p_memsz;
        entry.p_align = 8;
        phdrTable.add(&entry, sizeof(Elf64_Phdr));
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
        entry.p_align = 0x1000; // Rip the alignment from original elf file
        phdrTable.add(&entry, sizeof(Elf64_Phdr));
    }
#if 0
    {
        Elf64_Phdr entry = interpSegment.getProgramHeader();
        entry.p_type = PT_INTERP;
        entry.p_flags = PF_R;
        entry.p_align = 1;
        phdrTable.add(&entry, sizeof(Elf64_Phdr));
    }
#endif
    phdrTableSegment.add(&phdrTable);

    // Section header table
    Section shdrTable(".shdr_table");
    {
        Elf64_Shdr entry = shdrTable.getSectionHeader(); // Program Table Header
        entry.sh_type = SHT_NULL;
        entry.sh_addralign = 1;
        shdrTable.add(&entry, sizeof(Elf64_Shdr));
    }
    {
        Elf64_Shdr entry = symtab.getSectionHeader();
        entry.sh_addr = 0;
        entry.sh_type = SHT_SYMTAB;
        entry.sh_addralign = 8;
        entry.sh_entsize = sizeof(Elf64_Sym);
        entry.sh_link = 2;
        entry.sh_flags = 0;
        entry.sh_info = 0;
        shdrTable.add(&entry, sizeof(Elf64_Shdr));
    }
    {
        Elf64_Shdr entry = strtab.getSectionHeader();
        entry.sh_addr = 0;
        entry.sh_type = SHT_STRTAB;
        entry.sh_entsize = sizeof(Elf64_Sym);
        entry.sh_addralign = 1;
        entry.sh_entsize = 0;
        entry.sh_link = 0;
        entry.sh_flags = 0;
        entry.sh_info = 0;
        shdrTable.add(&entry, sizeof(Elf64_Shdr));
    }
    debugSegment.add(&shdrTable);

    // entry point
    address_t entry_pt = 0;
    for(auto chunk : chunkList->genericIterable()) {
        if(!strcmp(chunk->getName().c_str(), "_start"))
            entry_pt = chunk->getAddress();
    }
    header->e_entry = entry_pt;
    header->e_phoff = phdrTableSegment.getFileOff();
    header->e_phnum = phdrTable.getSize() / sizeof(Elf64_Phdr);
    header->e_shoff = shdrTable.getFileOff();
    header->e_shnum = shdrTable.getSize() / sizeof(Elf64_Shdr);
    header->e_shstrndx = 2;

    // Write to file
    std::ofstream fs(filename, std::ios::out | std::ios::binary);
    // First load old data that is still relevant
    fs << loadRESegment;
    fs << loadRWSegment;
    fs << hdrSegment;
    fs << phdrTableSegment;
    fs << loadTextSegment;
    fs << debugSegment;
    fs.close();
}
