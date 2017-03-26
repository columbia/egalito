#include <set>
#include <cstring>
#include <fstream>
#include <sstream>  // for generating section names
#include <elf.h>
#include <sys/stat.h>  // for chmod
#include "elfgen.h"
#include "log/registry.h"
#include "log/log.h"

std::ostream& operator<<(std::ostream &stream, ElfGen::Segment &rhs) {
    LOG(1, "offset: 0x" << std::hex << rhs.getFileOff());
    stream.seekp(rhs.getFileOff());
    for(auto section : rhs.getSections()) {
        stream << *section;
    }
    return stream;
}

void ElfGen::Segment::add(ElfGen::Section *sec) {
    sec->setFileOff(fileOffset + size);
    sec->setAddress(address + size);
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
    long int diff = 0;
    for(auto sec : sections) {
        sec->setFileOff(offset + diff);
        diff += sec->getSize();
    }
    fileOffset = offset;
}

void ElfGen::Segment::setAddress(address_t addr) {
    long int diff = 0;
    for(auto sec : sections) {
        sec->setAddress(addr + diff);
        diff += sec->getSize();
    }
    address = addr;
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
    entry->sh_addr = address;
    return entry;
}

ElfGen::Metadata::~Metadata() {
    for(auto segment : segmentList)
        delete segment;
    for(auto phdr : phdrList)
        delete phdr;
    for(auto shdr : shdrList) {
        delete shdr.first;
        delete shdr.second;
    }
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
    if(elfSpace->getElfMap()->isDynamic()) {
        makeDynamicSymbolInfo();
        makePLT();
        makeDynamic();
    }
    makePhdrTable();
    phdrTableSegment->setAddress(getNextFreeAddress(visibleSegment));
    phdrTableSegment->setFileOff(getNextFreeOffset());
    hiddenSegment->setFileOff(getNextFreeOffset());
    makeShdrTable();
    updateEntryPoint();

    // Write to file
    std::ofstream fs(filename, std::ios::out | std::ios::binary);
    for(auto segment : data.getSegmentList()) {
        LOG(1, "serialize segment at " << segment->getFirstSection()->getName());
        fs << *segment;
    }
    fs.close();

    chmod(filename.c_str(), 0755);
}

void ElfGen::makeOriginalSegments() {
    // Elf Header
    auto elfMap = elfSpace->getElfMap();
    headerSegment = new Segment();
    headerSegment->setFileOff(0);
    headerSegment->setAddress(0);
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
    auto loadRESegment = new Segment();
    loadRESegment->setFileOff(rodata->p_offset);
    loadRESegment->setAddress(rodata->p_vaddr);
    loadRESegment->add(new Section(".old_re", elfMap->getMap(), rodata->p_memsz));
    addSegment(loadRESegment, PT_LOAD, PF_R | PF_X, rodata->p_align);

    // Read Write data
    if(rwdata) {  // some executables may have no data to load!
        auto loadRWSegment = new Segment();
        char *loadRWVirtualAdress = elfMap->getCharmap() + loadRESegment->getFileOff();
        loadRWSegment->add(new Section(".old_rw", static_cast<void *>(loadRWVirtualAdress), rwdata->p_memsz));
        loadRWSegment->setFileOff(rwdata->p_offset);
        loadRWSegment->setAddress(rwdata->p_vaddr);
        addSegment(loadRWSegment, PT_LOAD, PF_R | PF_W, rwdata->p_align);
    }

    addSegment(headerSegment);  // overwrite part of loadRESegment
}

void ElfGen::makeNewTextSegment() {
    // Text
    size_t loadOffset = getNextFreeOffset();
    loadOffset += 0xfff - ((loadOffset + 0xfff) & 0xfff);
#if 1  // split separate pages into their own LOAD sections
    std::set<address_t> pagesUsed;
    for(auto func : CIter::functions(elfSpace->getModule())) {
        address_t start = func->getAddress() & ~0xfff;
        address_t end = ((func->getAddress() + func->getSize()) + 0xfff) & ~0xfff;
        for(address_t page = start; page < end; page += 0x1000) {
            LOG(1, "code uses page " << std::hex << page);
            pagesUsed.insert(page);
        }
    }

    std::set<address_t>::iterator i = pagesUsed.begin();
    size_t totalSize = 0;
    while(i != pagesUsed.end()) {
        size_t size = 0;
        std::set<address_t>::iterator j = i;
        while(j != pagesUsed.end() && (*j) == (*i) + size) {
            j++;
            size += 0x1000;
        }

        LOG(1, "map " << std::hex << *i << " size " << size);

        // intentionally leave visibleSegment set after last iteration
        visibleSegment = new Segment();
        visibleSegment->setAddress(backing->getBase() + totalSize);
        visibleSegment->setFileOff(loadOffset + totalSize);
        std::ostringstream sectionName;
        sectionName << ".text.0x" << std::hex << *i;
        auto textSection = new Section(sectionName.str().c_str(), (const uint8_t *)*i, size);
        visibleSegment->add(textSection);
        addShdr(textSection, SHT_PROGBITS);
        addSegment(visibleSegment, PT_LOAD, PF_R | PF_X, 0x1000);

        totalSize += size;
        i = j;
    }
#else
    visibleSegment = new Segment();
    visibleSegment->setAddress(backing->getBase());
    visibleSegment->setFileOff(loadOffset);
    auto textSection = new Section(".text", (const uint8_t *)backing->getBase(), backing->getSize());
    visibleSegment->add(textSection);
    addShdr(textSection, SHT_PROGBITS);
    addSegment(visibleSegment, PT_LOAD, PF_R | PF_X, 0x1000);
#endif

    // Interp
    auto elfMap = elfSpace->getElfMap();
    if(elfMap->isDynamic()) {
        Section *interpSection = new Section(".interp", elfMap->getInterpreter(), std::strlen(interpreter));
        Segment *interpSegment = new Segment();
        interpSegment->setAddress(getNextFreeAddress(visibleSegment));
        interpSegment->setFileOff(getNextFreeOffset());
        interpSegment->add(interpSection);
        visibleSegment->add(interpSection);
        addShdr(interpSection, SHT_PROGBITS);
        addSegment(interpSegment, PT_INTERP, PF_R, 0x1);
    }
}

void ElfGen::makeSymbolInfo() {
    // Symbol Table
    Section *symtab = new Section(".symtab");

    std::vector<char> strtabData;
    size_t count = 0;
    {  // add null symbol
        strtabData.push_back('\0');
        Elf64_Sym symbol;
        symbol.st_name = 0;
        symbol.st_info = 0;
        symbol.st_other = STV_DEFAULT;
        symbol.st_shndx = 0;
        symbol.st_value = 0;
        symbol.st_size = 0;
        symtab->add(static_cast<void *>(&symbol), sizeof(symbol));
        count ++;
    }

    for(auto func : CIter::functions(elfSpace->getModule())) {
        // add name to string table
        auto name = func->getName();
        auto index = strtabData.size();
        strtabData.insert(strtabData.end(), name.begin(), name.end());
        strtabData.push_back('\0');

        // generate new Symbol from new address
        Elf64_Sym sym = generateSymbol(func, func->getSymbol(), index);
        symtab->add(static_cast<void *>(&sym), sizeof(sym));
        count ++;

        for(auto alias : func->getSymbol()->getAliases()) {
            // add name to string table
            auto name = std::string(alias->getName());
            auto index = strtabData.size();
            strtabData.insert(strtabData.end(), name.begin(), name.end());
            strtabData.push_back('\0');

            // generate new Symbol from new address
            Elf64_Sym sym = generateSymbol(func, alias, index);
            symtab->add(static_cast<void *>(&sym), sizeof(sym));
            count ++;
        }
    }

    Section *strtab = new Section(".strtab");
    strtab->add(strtabData.data(), strtabData.size());

    hiddenSegment = new Segment();
    hiddenSegment->add(symtab);
    hiddenSegment->add(strtab);
    addSegment(hiddenSegment);

    int strtab_id = addShdr(strtab, SHT_STRTAB);
    addShdr(symtab, SHT_SYMTAB, strtab_id);
    data.getLastShdr().second->sh_info = count;
}

void ElfGen::makeDynamicSymbolInfo() {
    // Symbol Table
    Section *dsymtab = new Section(".dsymtab");
    std::vector<char> dstrtabData = {'\0'};
    for(auto symbol : *elfSpace->getDynamicSymbolList()) {
        // add name to string table
        std::string name = symbol->getName();
        auto index = dstrtabData.size();
        dstrtabData.insert(dstrtabData.end(), name.begin(), name.end());
        dstrtabData.push_back('\0');

        // generate new Symbol from new address
        Elf64_Sym sym = generateSymbol(nullptr, symbol, index);
        dsymtab->add(static_cast<void *>(&sym), sizeof(sym));
    }

    Section *dstrtab = new Section(".dstrtab");
    dstrtab->add(dstrtabData.data(), dstrtabData.size());

    visibleSegment->add(dsymtab);
    visibleSegment->add(dstrtab);

    int dstrtab_id = addShdr(dstrtab, SHT_STRTAB);
    addShdr(dsymtab, SHT_DYNSYM, dstrtab_id);
}

void ElfGen::makePLT() {
    auto elfMap = elfSpace->getElfMap();

    Elf64_Shdr *pltShdr = new Elf64_Shdr();
    memcpy(pltShdr, elfMap->findSectionHeader(".plt"), sizeof(Elf64_Shdr));
    pltShdr->sh_name = data.getShdrListSize();
    Section *pltSection = new Section(".plt");
    data.addShdr(pltSection, pltShdr);

    Elf64_Shdr *relaPltShdr = new Elf64_Shdr();
    memcpy(relaPltShdr, elfMap->findSectionHeader(".rela.plt"), sizeof(Elf64_Shdr));
    relaPltShdr->sh_name = data.getShdrListSize();
    Section *relaPltSection = new Section(".rela.plt");
    data.addShdr(relaPltSection, relaPltShdr);
}

void ElfGen::makeDynamic() {
    Segment *dynamicSegment = new Segment();
    Section *dynamicSection = new Section(".dynamic");
    dynamicSegment->add(dynamicSection);
    addShdr(dynamicSection, SHT_DYNAMIC);
    addSegment(dynamicSegment, PT_DYNAMIC, PF_R | PF_W, 0x8);
}

void ElfGen::makePhdrTable() {
    // Note: we overwrite the previous phdrs list. This only works if we have
    // at most as many entries as were originally present.
    this->phdrTableSegment = new Segment();
    this->phdrTableSegment->setFileOff(sizeof(Elf64_Ehdr));
    this->phdrTableSegment->setAddress(0);
    Section *phdrTable = new Section(".phdr_table");
    {
        Elf64_Phdr *entry = phdrTableSegment->makeProgramHeader(PT_PHDR, PF_R | PF_X, 8); // Program Table Header
        entry->p_memsz = (data.getPhdrListSize() + 1) * sizeof(Elf64_Phdr);
        entry->p_filesz = entry->p_memsz;
        phdrTable->add(entry, sizeof(Elf64_Phdr));
    }
    for(auto phdr : data.getPhdrList()) {
        phdrTable->add(phdr, sizeof(Elf64_Phdr));
    }
    phdrTableSegment->add(phdrTable);
    addSegment(phdrTableSegment);
}

void ElfGen::makeShdrTable() {
    // Allocate new space for the shdrs, and don't map them into memory.
    // NOTE: shstrtab must be the last section in the ELF (to set e_shstrndx).
    auto shstrtab = new Section(".shstrtab");
    addShdr(shstrtab, SHT_STRTAB);

    for(auto p : data.getShdrList()) {
        auto section = p.first;
        auto shdr = p.second;
        shdr->sh_offset = section->getFileOff();
        shdr->sh_addr = section->getAddress();
        shdr->sh_name = shstrtab->getSize();
        LOG(1, "for " << section->getName() << ", sh_name is [" << shdr->sh_name << "]");
        shstrtab->add(section->getName().c_str(),
            section->getName().size() + 1);
    }
    // modify sh string table location in file
    data.getLastShdr().second->sh_size = shstrtab->getSize();
    data.getLastShdr().second->sh_offset = getNextFreeOffset(); // HERE

    hiddenSegment->add(shstrtab);


    shdrTable = new Section(".shdr_table");
    for(auto shdr : data.getShdrList()) {
        shdrTable->add(shdr.second, sizeof(Elf64_Shdr));
    }

    hiddenSegment->add(shdrTable);
}

void ElfGen::updateEntryPoint() { // NEEDS TO BE UPDATED
    // Update entry point in existing segment
    Elf64_Ehdr *header = headerSegment->getFirstSection()->castAs<Elf64_Ehdr>();
    address_t entry_pt = 0;
    if(auto start = CIter::named(elfSpace->getModule()->getFunctionList())
        ->find("_start")) {

        entry_pt = elfSpace->getElfMap()->getBaseAddress()
            + start->getAddress();
    }
    header->e_entry = entry_pt;
    header->e_phoff = phdrTableSegment->getFileOff();
    header->e_phnum = phdrTableSegment->getFirstSection()->getSize() / sizeof(Elf64_Phdr);
    header->e_shoff = shdrTable->getFileOff(); // HERE
    header->e_shnum = shdrTable->getSize() / sizeof(Elf64_Shdr); // HERE
    header->e_shstrndx = data.getShdrListSize() - 1;  // assume .shstrtab is last
}


size_t ElfGen::getNextFreeOffset() {
    size_t maxOffset = 0;
    for(auto segment : data.getSegmentList()) {
        auto offset = segment->getFileOff() + segment->getSize();
        if(offset > maxOffset) maxOffset = offset;
    }
    return maxOffset;
}

address_t ElfGen::getNextFreeAddress(Segment *segment) {
    address_t maxAddress = 0;
    for(auto section : segment->getSections()) {
        auto address = section->getAddress() + section->getSize();
        if(address > maxAddress) maxAddress = address;
    }
    return maxAddress;
}

Elf64_Sym ElfGen::generateSymbol(Function *func, Symbol *sym, size_t strtabIndex) {
    Elf64_Sym symbol;
    symbol.st_name = static_cast<Elf64_Word>(strtabIndex);
    symbol.st_info = ELF64_ST_INFO(Symbol::bindFromInternalToElf(sym->getBind()),
                                   Symbol::typeFromInternalToElf(sym->getType()));
    symbol.st_other = STV_DEFAULT;
    symbol.st_shndx = func ? 1 : 3;  // dynamic symbols have func==nullptr
    symbol.st_value = func ? func->getAddress() : 0;
    symbol.st_size = func ? func->getSize() : 0;
    return std::move(symbol);
}

void ElfGen::addSegment(Segment *segment) {
    data.addSegment(segment);
}
void ElfGen::addSegment(Segment *segment, Elf64_Word p_type, Elf64_Word p_flags, Elf64_Xword p_align) {
    Elf64_Phdr *entry = segment->makeProgramHeader(p_type, p_flags, p_align);
    data.addPhdr(entry);

    data.addSegment(segment);
}

int ElfGen::addShdr(Section *section, Elf64_Word type, int link) {
    Elf64_Shdr *entry = section->makeSectionHeader();
    entry->sh_name = data.getShdrListSize();

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

    data.addShdr(section, entry);
    return static_cast<int>(data.getShdrListSize() - 1);
}
