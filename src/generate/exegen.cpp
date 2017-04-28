#include <set>
#include <cstring>
#include <fstream>
#include <sstream>  // for generating section names
#include <elf.h>
#include <sys/stat.h>  // for chmod
#include "exegen.h"
#include "makeplt.h"
#include "chunk/plt.h"
#include "log/registry.h"
#include "log/log.h"

ExeGen::Metadata::Metadata() : segmentList(SEGMENT_TYPES),
    stringTableList(STRING_TABLE_TYPES) {

    for(int idx = SEGMENT_TYPES - 1; idx >= 0; idx --) {
        segmentList[idx] = new Segment();
    }

    stringTableList[SH] = new Section(".shstrtab", SHT_STRTAB);
    stringTableList[DYN] = new Section(".dynstr", SHT_STRTAB);
    stringTableList[SYM] = new Section(".strtab", SHT_STRTAB);
}

ExeGen::Metadata::~Metadata() {
    for(auto segment : segmentList)
        delete segment;
}

ExeGen::ExeGen(ElfSpace *space, MemoryBacking *backing, std::string filename,
    const char *interpreter) : elfSpace(space), backing(backing),
    filename(filename), interpreter(interpreter) {
    // data = Metadata();
    if(!interpreter) {
        this->interpreter = space->getElfMap()->getInterpreter();
    }
}

void ExeGen::generate() {
    makeHeader();
    makeRWData();
    makeText();
    makeSymbolInfo();
    if(elfSpace->getElfMap()->isDynamic()) {
        makeDynamicSymbolInfo();
        makePLT();
        makeDynamic();
    }
    updateOffsetAndAddress();
    makeShdrTable();
    makePhdrTable();
    updateHeader();

    // Write to file
    serializeSegments();

    chmod(filename.c_str(), 0755);
}

void ExeGen::makeHeader() {
    // Elf Header
    auto elfMap = elfSpace->getElfMap();
    data[Metadata::HEADER]->setOffset(0, Segment::Offset::FIXED);
    data[Metadata::HEADER]->add((new Section(".elfheader"))
        ->with(elfMap->getMap(), sizeof(ElfXX_Ehdr)));
    // Update entry point in existing segment
    ElfXX_Ehdr *header = data[Metadata::HEADER]->getFirstSection()->castAs<ElfXX_Ehdr>();
    address_t entry_pt = 0;
    if(auto start = CIter::named(elfSpace->getModule()->getFunctionList())
        ->find("_start")) {

        entry_pt = elfSpace->getElfMap()->getBaseAddress()
            + start->getAddress();
    }
    header->e_entry = entry_pt;
}

void ExeGen::makeRWData() {// Elf Header
    auto elfMap = elfSpace->getElfMap();
    ElfXX_Phdr *rodata = nullptr;
    ElfXX_Phdr *rwdata = nullptr;
    for(auto original : elfMap->getSegmentList()) {
        auto segment = static_cast<ElfXX_Phdr *>(original);
        if(segment->p_type == PT_LOAD) {
            if(segment->p_flags == (PF_R | PF_X)) rodata = segment;
            if(segment->p_flags == (PF_R | PF_W)) rwdata = segment;
        }
    }
    data[Metadata::RODATA]->add((new Section(".old_ro"))
        ->with(elfMap->getCharmap(), rodata->p_memsz));
    data[Metadata::RODATA]->setOffset(rodata->p_offset, Segment::Offset::ORIGINAL);
    data[Metadata::RODATA]->setAddress(rodata->p_vaddr, Segment::Address::ORIGINAL);
    data[Metadata::RODATA]->setPhdrInfo(rodata->p_type, rodata->p_flags, rodata->p_align);

    // Read Write data
    if(rwdata) {  // some executables may have no data to load!
        char *loadRWVirtualAdress = elfMap->getCharmap() + rodata->p_offset;
        data[Metadata::RWDATA]->add((new Section(".old_rw"))
            ->with(static_cast<void *>(loadRWVirtualAdress), rwdata->p_memsz));
        data[Metadata::RWDATA]->setOffset(rwdata->p_offset, Segment::Offset::ORIGINAL);
        data[Metadata::RWDATA]->setAddress(rwdata->p_vaddr, Segment::Address::ORIGINAL);
        data[Metadata::RWDATA]->setPhdrInfo(rwdata->p_type, rwdata->p_flags, rwdata->p_align);
    }
}

void ExeGen::makeText() {
    size_t loadOffset = getNextFreeOffset();
    loadOffset += 0xfff - ((loadOffset + 0xfff) & 0xfff);

    // split separate pages into their own LOAD sections
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

        // intentionally leave VISIBLE Segment set after last iteration
        data[Metadata::VISIBLE]->setOffset(loadOffset + totalSize, Segment::Offset::FIXED);
        data[Metadata::VISIBLE]->setAddress(backing->getBase() + totalSize, Segment::Address::FIXED);
        data[Metadata::VISIBLE]->setPhdrInfo(PT_LOAD, PF_R | PF_X, 0x1000);
        std::ostringstream sectionName;
        sectionName << ".text.0x" << std::hex << *i;
        auto textSection = new Section(sectionName.str().c_str(), SHT_PROGBITS);
        textSection->add((const uint8_t *)*i, size);
        data[Metadata::VISIBLE]->add(textSection);

        totalSize += size;
        i = j;
    }

    // Interp
    auto elfMap = elfSpace->getElfMap();
    if(elfMap->isDynamic()) {
        Section *interpSection = new Section(".interp", SHT_PROGBITS);
        interpSection->add(elfMap->getInterpreter(), std::strlen(interpreter) + 1);
        data[Metadata::INTERP]->setAddressType(Segment::Address::DEPENDENT, data[Metadata::VISIBLE]);
        data[Metadata::INTERP]->add(interpSection);
        data[Metadata::INTERP]->setPhdrInfo(PT_INTERP, PF_R, 0x1);

        data[Metadata::VISIBLE]->add(interpSection);
    }
}

void ExeGen::makeSymbolInfo() {
    // Symbol Table
    auto symtab = new SymbolTableSection(".symtab", SHT_SYMTAB);
    auto strtab = data.getStrTable(Metadata::SYM);

    size_t count = 0;
    {  // add null symbol
        ElfXX_Sym symbol;
        symbol.st_name = strtab->add("", 1);  // add empty name
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
        auto index = strtab->add(func->getName(), true);
        symtab->add(func, func->getSymbol(), index);

        for(auto alias : func->getSymbol()->getAliases()) {
            // add name to string table
            auto name = std::string(alias->getName());
            auto index = strtab->add(name, true);
            symtab->add(func, alias, index);
        }
    }

    symtab->setSectionLink(strtab);
    data[Metadata::HIDDEN]->add(symtab);
    data[Metadata::HIDDEN]->add(strtab);
}

void ExeGen::makeDynamicSymbolInfo() {
    // Symbol Table
    auto dynsym = new SymbolTableSection(".dynsym", SHT_DYNSYM);
    auto dynstr = data.getStrTable(Metadata::DYN);
    for(auto symbol : *elfSpace->getDynamicSymbolList()) {
        // add name to string table
        std::string name = symbol->getName();
        auto index = dynstr->add(name, true);

        // generate new Symbol from new address
        dynsym->add(nullptr, symbol, index);
    }

    dynsym->setSectionLink(dynstr);
    data[Metadata::VISIBLE]->add(dynsym);
    data[Metadata::VISIBLE]->add(dynstr);
}

void ExeGen::makePLT() {
    auto elfMap = elfSpace->getElfMap();
    auto oldPLT = (
                   elfMap->findSection(".plt"))->getHeader();
    if(!oldPLT) return;

    auto dynsym = dynamic_cast<SymbolTableSection *>(
        data[Metadata::VISIBLE]->findSection(".dynsym"));
    if(!dynsym) return;

    // make plt
    originalPLT.makePLT(elfSpace,
        elfSpace->getModule()->getPLTList(),
        dynsym);

    auto pltSection = new Section(".plt", SHT_PROGBITS);

    pltSection->setAddress(oldPLT->sh_addr);
    pltSection->addNullBytes(oldPLT->sh_size);

    data[Metadata::RODATA]->add(pltSection);

    // make relocs
    // auto pltRelocSection = new RelocationSection(".rela.plt", SHT_RELA);
    // pltRelocSection->setTargetSection(pltSection);
    // pltRelocSection->setSectionLink(dynsym);
    // pltRelocSection->add(originalPLT.getRelocations());
    // data[Metadata::RODATA]->add(pltRelocSection);
}

void ExeGen::makeDynamic() {
    Section *dynamicSection = new Section(".dynamic", SHT_DYNAMIC);
    auto dynstr = data.getStrTable(Metadata::DYN);

    std::vector<ElfXX_Dyn> dynamicData;
    auto elfMap = elfSpace->getElfMap();
    ElfXX_Phdr *oldDynamic = nullptr;
    for(auto original : elfMap->getSegmentList()) {
        auto segment = static_cast<ElfXX_Phdr *>(original);
        if(segment->p_type == PT_DYNAMIC) {
            oldDynamic = segment;
            break;
        }
    }
    LOG(1, "old dynamic offset " << oldDynamic->p_offset);
    unsigned long *oldList = reinterpret_cast<unsigned long *>(
        elfMap->getCharmap() + oldDynamic->p_offset);
    while(oldList[0] != DT_NULL) {
        LOG(1, "old dynamic list entry tag " << oldList[0]);
        ElfXX_Sxword tag = oldList[0];
        auto value = oldList[1];
        if(tag == DT_NEEDED) {
            const char *lib = elfMap->getDynstrtab() + value;
            LOG(1, "I think the lib is [" << lib << "]");
            auto index = dynstr->add(lib, std::strlen(lib) + 1);

            dynamicData.push_back({tag, index});
        }
        oldList += 2;
    }

    auto dynsym = dynamic_cast<SymbolTableSection *>(
        data[Metadata::VISIBLE]->findSection(".dynsym"));
    dynamicData.push_back({DT_SYMTAB, dynsym->getOffset()});
    dynamicData.push_back({DT_STRTAB, data.getStrTable(Metadata::DYN)->getOffset()});

    auto relaplt = dynamic_cast<RelocationSection *>(
        data[Metadata::RODATA]->findSection(".rela.plt"));
    dynamicData.push_back({DT_PLTGOT, 0x201000});
    dynamicData.push_back({DT_PLTRELSZ, relaplt->getSize()});
    dynamicData.push_back({DT_PLTREL, DT_RELA});

    dynamicData.push_back({DT_NULL, 0});
    dynamicSection->add(static_cast<void *>(dynamicData.data()),
        dynamicData.size() * sizeof(ElfXX_Dyn));

    data[Metadata::DYNAMIC]->setOffsetType(Segment::Offset::ASSIGNABLE);
    data[Metadata::DYNAMIC]->setAddressType(Segment::Address::ASSIGNABLE);
    data[Metadata::DYNAMIC]->add(dynamicSection);
    data[Metadata::DYNAMIC]->setPhdrInfo(PT_DYNAMIC, PF_R | PF_W, 0x8);
}

void ExeGen::makePhdrTable() {
    // Note: we overwrite the previous phdrs list. This only works if we have
    // at most as many entries as were originally present.
    data[Metadata::PHDR_TABLE]->setPhdrInfo(PT_PHDR, PF_R | PF_X, 8);
    data[Metadata::PHDR_TABLE]->setOffset(sizeof(ElfXX_Ehdr), Segment::Offset::FIXED);
    //data[Metadata::PHDR_TABLE]->setAddress(0);
    std::vector<Elf64_Phdr *> phdrList;
    for(auto seg : data.getSegmentList()) {
        if(seg->hasPhdr()) {
            phdrList.push_back(seg->makePhdr());
        }
    }
    Section *phdrTable = new Section(".phdr_table");
    {
        ElfXX_Phdr *entry = phdrList[0];  // assume first phdr is the PHDR entry
        entry->p_memsz = (phdrList.size() + 1) * sizeof(ElfXX_Phdr);
        entry->p_filesz = entry->p_memsz;
    }
    for(auto phdr : phdrList) {
        phdrTable->add(static_cast<void *>(phdr), sizeof(ElfXX_Phdr));
    }
    data[Metadata::PHDR_TABLE]->add(phdrTable);
    data[Metadata::PHDR_TABLE]->setPhdrInfo(PT_PHDR, PF_R | PF_X, 0x8);
}

void ExeGen::makeShdrTable() {
    auto shstrtab = data.getStrTable(Metadata::SH);
    data[Metadata::HIDDEN]->add(shstrtab);

    // Allocate new space for the shdrs, and don't map them into memory.
    std::vector<std::pair<Section *, ElfXX_Shdr *>> shdrList;
    std::map<Section *, size_t> sectionLookup;

    size_t index = 0;
    auto nullSection = new Section("", SHT_NULL);
    auto nullShdr = nullSection->makeShdr(index++, shstrtab->getSize());
    shstrtab->add(nullSection->getName(), true);  // include NULL terminator
    sectionLookup[nullSection] = 0;
    shdrList.push_back(std::make_pair(nullSection, nullShdr));
    for(auto seg : data.getSegmentList()) {
        if(seg->getPType() == PT_INTERP) continue;

        for(auto sec : seg->getSections()) {
            if(sec->hasShdr()) {
                auto shdr = sec->makeShdr(index++, shstrtab->getSize());
                shstrtab->add(sec->getName(), true);  // include NULL terminator

                sectionLookup[sec] = shdrList.size();
                shdrList.push_back(std::make_pair(sec, shdr));
            }
        }
    }
    // expand shstrtab to include the string for itself & following sections
    shdrList[sectionLookup[shstrtab]].second->sh_size = shstrtab->getSize();

    auto shdrTable = new Section(".shdr_table");
    for(auto p : shdrList) {
        auto sec = p.first;
        auto shdr = p.second;
        shdr->sh_link = sectionLookup[sec->getSectionLink()];
        shdrTable->add(shdr, sizeof(*shdr));
    }
    data[Metadata::HIDDEN]->add(shdrTable);

    ElfXX_Ehdr *header = data[Metadata::HEADER]->getFirstSection()->castAs<ElfXX_Ehdr>();
    header->e_shstrndx = sectionLookup[data.getStrTable(Metadata::SH)];

    for(auto shdr : shdrList) delete shdr.second;
    delete nullSection;
}

void ExeGen::updateOffsetAndAddress() {
    for(size_t idx = Metadata::HEADER; idx < Metadata::SEGMENT_TYPES;
        idx ++) {

        auto t = static_cast<Metadata::SegmentType>(idx);
        if(data[t]->getOffset().type == Segment::Offset::ASSIGNABLE) {
            size_t offset = getNextFreeOffset();
            if(data[t]->getPType() == PT_LOAD) {
                data[t]->setOffset(roundUpToPageAlign(offset));
            } else {
                if(t == Metadata::HIDDEN)
                    LOG(1, "OFFSET: " << offset);
                data[t]->setOffset(offset);
            }
        }
        if(data[t]->getAddress().type == Segment::Address::ASSIGNABLE) {
            data[t]->setAddress(getNextFreeAddress());
        }
    }
    // Update dependent segments
    for(size_t idx = Metadata::HEADER; idx < Metadata::SEGMENT_TYPES;
        idx ++) {
        auto t = static_cast<Metadata::SegmentType>(idx);
        auto address = data[t]->getAddress();
        if(address.type != Segment::Address::DEPENDENT) {
            continue;
        }
        auto name = data[t]->getFirstSection()->getName();
        auto section = address.dependent->findSection(name);
        data[t]->setAddress(section->getAddress());
    }
}

void ExeGen::updateHeader() {
    ElfXX_Ehdr *header = data[Metadata::HEADER]->getFirstSection()->castAs<ElfXX_Ehdr>();
    header->e_phoff = data[Metadata::PHDR_TABLE]->getOffset().off;
    header->e_phnum = data[Metadata::PHDR_TABLE]->getFirstSection()->getSize() / sizeof(Elf64_Phdr);
    Section *shdrTable = data[Metadata::HIDDEN]->findSection(".shdr_table");
    header->e_shoff = shdrTable->getOffset();
    header->e_shnum = shdrTable->getSize() / sizeof(Elf64_Shdr);
}

void ExeGen::serializeSegments() {
    std::ofstream fs(filename, std::ios::out | std::ios::binary);
    for(auto segment : data.getSegmentList()) {
        if(segment->getSections().size() == 0 ||
            segment->getAddress().type != Segment::Address::ORIGINAL) {
            continue;
        }
        LOG(1, "serialize segment at " << segment->getFirstSection()->getName());
        fs << *segment;
    }

    for(auto segment : data.getSegmentList()) {
        if(segment->getSections().size() == 0 ||
            segment->getAddress().type == Segment::Address::ORIGINAL) {
            continue;
        }
        LOG(1, "serialize segment at " << segment->getFirstSection()->getName());
        fs << *segment;
    }
    fs.close();
}

size_t ExeGen::getNextFreeOffset() {
    size_t maxOffset = 0;
    for(auto seg : data.getSegmentList()) {
        auto offset = seg->getOffset().off + seg->getSize();
        if(offset > maxOffset) maxOffset = offset;
    }
    return maxOffset;
}

size_t ExeGen::roundUpToPageAlign(size_t offset) {
    return (offset + 0xfff) & ~0xfff;
}

address_t ExeGen::getNextFreeAddress() {
    address_t maxAddress = 0;
    for(auto segment : data.getSegmentList()) {
        for(auto section : segment->getSections()) {
            auto address = section->getAddress() + section->getSize();
            if(address > maxAddress) maxAddress = address;
        }
    }
    return maxAddress;
}
