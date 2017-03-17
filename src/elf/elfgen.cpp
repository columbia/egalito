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

void ElfGen::Segment::add(ElfGen::Section *sec) {
    sec->setFileOff(fileOffset + size);
    size += sec->getSize();
    sections.push_back(sec);
}

Elf64_Phdr* ElfGen::Segment::makeProgramHeader(Elf64_Word p_type, Elf64_Word p_flags, Elf64_Xword p_align) const {
    Elf64_Phdr *entry = new Elf64_Phdr();
    entry->p_type = p_type;
    entry->p_flags = p_flags;
    entry->p_align = p_align;
    entry->p_offset = fileOffset;
    entry->p_vaddr = address;
    entry->p_paddr = entry->p_vaddr;
    entry->p_memsz = size;
    entry->p_filesz = size;
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

void ElfGen::Section::add(const void *data, size_t size) {
    add(static_cast<const char *>(data), size);
}
void ElfGen::Section::add(const char *data, size_t size) {
    this->data.append(data, size);
    this->size += size;
}

Elf64_Shdr *ElfGen::Section::makeSectionHeader() const {
    Elf64_Shdr *entry = new Elf64_Shdr();
    entry->sh_offset = fileOffset;
    entry->sh_size = size;
    return entry;
}

ElfGen::ElfGen(ElfSpace *space, MemoryBacking *backing, std::string filename,
    const char *interpreter) : elfSpace(space), backing(backing),
    filename(filename), interpreter(interpreter) {

    if(!interpreter) {
        this->interpreter = space->getElfMap()->getInterpreter();
    }
}

void ElfGen::generate() {
    {  // add null entry to shdr list
        Section nullSection("");
        addShdr(&nullSection, SHT_NULL);
    }

    makeOriginalSegments();
    makeNewTextSegment();
    makeSymbolInfo();
    makePhdrTable();
    makeShdrTable();
    updateEntryPoint();

    // Write to file
    std::ofstream fs(filename, std::ios::out | std::ios::binary);
    for(auto segment : segments) {
        LOG(1, "serialize segment at " << segment->getFirstSection()->getName());
        fs << *segment;
    }
    fs.close();
}

void ElfGen::makeOriginalSegments() {
    // Elf Header
    auto elfMap = elfSpace->getElfMap();
    this->headerSegment = new Segment(0, 0);
    headerSegment->add(new Section(".elfheader", elfMap->getMap(), sizeof(Elf64_Ehdr)));

    Elf64_Phdr *rodata = nullptr;
    Elf64_Phdr *rwdata = nullptr;
    for(auto original : elfMap->getSegmentList()) {
        auto segment = static_cast<Elf64_Phdr *>(original);
        if(segment->p_type == PT_LOAD) {
            if(segment->p_flags == (PF_R | PF_X)) rodata = segment;
            if(segment->p_flags == (PF_R | PF_W)) rwdata = segment;
        }
    }

    // Rodata
    auto loadRESegment = new Segment(rodata->p_vaddr, rodata->p_offset);
    loadRESegment->add(new Section(".old_re", elfMap->getMap(), rodata->p_memsz));

    // Read Write data
    auto loadRWSegment = new Segment(rwdata->p_vaddr, rwdata->p_offset);
    char *loadRWVirtualAdress = elfMap->getCharmap() + loadRESegment->getFileOff();
    loadRWSegment->add(new Section(".old_rw", static_cast<void *>(loadRWVirtualAdress), rwdata->p_memsz));

    addSegment(loadRESegment, PT_LOAD, PF_R | PF_X, rodata->p_align);
    addSegment(loadRWSegment, PT_LOAD, PF_R | PF_W, rwdata->p_align);
    addSegment(headerSegment);  // overwrite part of loadRESegment
}

void ElfGen::makeNewTextSegment() {
    // Text
    size_t loadOffset = getNextFreeOffset();
    loadOffset += 0xfff - ((loadOffset + 0xfff) & 0xfff);
    Segment *loadTextSegment = new Segment(backing->getBase(), loadOffset);
    loadTextSegment->add(new Section(".text", (const uint8_t *)backing->getBase(), backing->getSize()));

    // Interp
    auto elfMap = elfSpace->getElfMap();
    for(auto original : elfMap->getSegmentList()) {
        auto segment = static_cast<Elf64_Phdr *>(original);
        if(segment->p_type == PT_INTERP) {
            loadTextSegment->add(new Section(".interp", static_cast<const void *>(interpreter), std::strlen(interpreter)));
            break;
        }
    }
    addSegment(loadTextSegment, PT_LOAD, PF_R | PF_X, 0x1000);
}

void ElfGen::makeSymbolInfo() {
    // Symbol Table
    Section *symtab = new Section(".symtab");
    std::vector<char> strtabData = {'\0'};
    for(auto chunk : elfSpace->getModule()->getChildren()->genericIterable()) {
        auto func = dynamic_cast<Function *>(chunk);
        if(!func) continue;

        // add name to string table
        auto name = chunk->getName();
        auto index = strtabData.size();
        strtabData.insert(strtabData.end(), name.begin(), name.end());
        strtabData.push_back('\0');

        // generate new Symbol from new address
        Elf64_Sym sym = generateSymbol(func, index);
        symtab->add(static_cast<void *>(&sym), sizeof(sym));
    }

    Section *strtab = new Section(".strtab");
    strtab->add(strtabData.data(), strtabData.size());

    Segment *symbolInfoSegment = new Segment(0, getNextFreeOffset());
    symbolInfoSegment->add(symtab);
    symbolInfoSegment->add(strtab);
    addSegment(symbolInfoSegment);

    int strtab_id = addShdr(strtab, SHT_STRTAB);
    addShdr(symtab, SHT_SYMTAB, strtab_id);
}

void ElfGen::makePhdrTable() {
    // Note: we overwrite the previous phdrs list. This only works if we have
    // at most as many entries as were originally present.
    this->phdrTableSegment = new Segment(0, sizeof(Elf64_Ehdr));
    Section *phdrTable = new Section(".phdr_table");
    {
        Elf64_Phdr *entry = phdrTableSegment->makeProgramHeader(PT_PHDR, PF_R | PF_X, 8); // Program Table Header
        entry->p_memsz = (phdrList.size() + 1) * sizeof(Elf64_Phdr);
        entry->p_filesz = entry->p_memsz;
        // phdrTable->add(entry, sizeof(Elf64_Phdr));
    }
    for(auto phdr : this->phdrList) {
        phdrTable->add(phdr, sizeof(Elf64_Phdr));
    }
    phdrTableSegment->add(phdrTable);
    addSegment(phdrTableSegment);
}

void ElfGen::makeShdrTable() {
    // Allocate new space for the shdrs, and don't map them into memory.
    this->shdrTableSegment = new Segment(0, getNextFreeOffset());
    Section *shdrTable = new Section(".shdr_table");
    for(auto shdr : shdrList) {
        shdrTable->add(shdr, sizeof(Elf64_Shdr));
    }
    shdrTableSegment->add(shdrTable);
    addSegment(shdrTableSegment);
}

void ElfGen::updateEntryPoint() {
    // Update entry point in existing segment
    Elf64_Ehdr *header = headerSegment->getFirstSection()->castAs<Elf64_Ehdr>();
    address_t entry_pt = 0;
    for(auto chunk : elfSpace->getModule()->getChildren()->genericIterable()) {
        if(!strcmp(chunk->getName().c_str(), "_start"))
            entry_pt = chunk->getAddress();
    }
    header->e_entry = entry_pt;
    header->e_phoff = phdrTableSegment->getFileOff();
    header->e_phnum = phdrTableSegment->getFirstSection()->getSize() / sizeof(Elf64_Phdr);
    header->e_shoff = shdrTableSegment->getFileOff();
    header->e_shnum = shdrTableSegment->getFirstSection()->getSize() / sizeof(Elf64_Shdr);
    header->e_shstrndx = 2;
}

size_t ElfGen::getNextFreeOffset() {
    size_t maxOffset = 0;
    for(auto segment : segments) {
        auto offset = segment->getFileOff() + segment->getSize();
        if(offset > maxOffset) maxOffset = offset;
    }
    return maxOffset;
}

Elf64_Sym ElfGen::generateSymbol(Function *func, size_t strtabIndex) {
    Symbol *sym = func->getSymbol();
    Elf64_Sym symbol;
    symbol.st_name = static_cast<Elf64_Word>(strtabIndex);
    symbol.st_info = ELF64_ST_INFO(Symbol::bindFromInternalToElf(sym->getBind()),
                                   Symbol::typeFromInternalToElf(sym->getType()));
    symbol.st_shndx = 1; // getSectionIndex();
    symbol.st_value = func->getAddress();
    symbol.st_size = func->getSize();
    return std::move(symbol);
}

void ElfGen::addSegment(Segment *segment) {
    segments.push_back(segment);
}
void ElfGen::addSegment(Segment *segment, Elf64_Word p_type, Elf64_Word p_flags, Elf64_Xword p_align) {
    Elf64_Phdr *entry = segment->makeProgramHeader(p_type, p_flags, p_align);
    phdrList.push_back(entry);

    segments.push_back(segment);
}

int ElfGen::addShdr(Section *section, Elf64_Word type, int link) {
    Elf64_Shdr *entry = section->makeSectionHeader();

    entry->sh_type = type;
    switch(type) {
    case SHT_SYMTAB:
        entry->sh_addralign = 8;
        break;
    default:
        entry->sh_addralign = 1;
        break;
    }

    if(type == SHT_SYMTAB) {
        entry->sh_entsize = sizeof(Elf64_Sym);
    }
    entry->sh_link = link;

    shdrList.push_back(entry);
    return static_cast<int>(shdrList.size() - 1);
}
