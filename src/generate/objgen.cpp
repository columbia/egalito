#include <set>
#include <cstring>
#include <fstream>
#include <sstream>
#include <elf.h>
#include "objgen.h"
#include "log/registry.h"
#include "log/log.h"

ObjGen::Sections::Sections() {
    header = new Section(".elfheader");
    strtab = new Section(".strtab", SHT_STRTAB);
    shstrtab = new Section(".shstrtab", SHT_STRTAB);
    sections.push_back(header);
    sections.push_back(strtab);
    sections.push_back(shstrtab);
}

ObjGen::Sections::~Sections() {
    for(auto section : sections) {
        delete section;
    }
}

Section *ObjGen::Sections::findSection(const std::string &name) {
    for(auto section : sections) {
        if(section->getName() == name) return section;
    }
    return nullptr;
}

ObjGen::ObjGen(ElfSpace *elfSpace, MemoryBacking *backing, std::string filename) :
    elfSpace(elfSpace), backing(backing), filename(filename) {
    sections = new Sections();
}

void ObjGen::generate() {
    LOG(1, "generating object file");
    makeHeader();
    makeText();
    makeSymbolInfo();
    makeShdrTable();
    updateOffsetAndAddress();
    updateShdrTable();
    updateHeader();
    serialize();
}

void ObjGen::makeHeader() {
    auto elfMap = elfSpace->getElfMap();
    sections->getHeader()->add(elfMap->getMap(), sizeof(ElfXX_Ehdr));

    ElfXX_Ehdr *header = sections->getHeader()->castAs<ElfXX_Ehdr>();
    header->e_type = ET_REL;
    header->e_entry = 0;
    header->e_phoff = 0;
    header->e_phentsize = 0;
    header->e_phnum = 0;
}

void ObjGen::makeText() {
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
        std::ostringstream sectionName;
        sectionName << ".text.0x" << std::hex << *i;
        auto textSection = new Section(sectionName.str().c_str(), SHT_PROGBITS);
        textSection->add((const uint8_t *)*i, size);
        sections->addSection(textSection);

        totalSize += size;
        i = j;
    }
}

void ObjGen::makeROData() {

}

void ObjGen::makeSymbolInfo() {
    auto symtab = new SymbolTableSection(".symtab", SHT_SYMTAB);
    auto strtab = sections->getStrTab();

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
    sections->addSection(symtab);
}

void ObjGen::makeShdrTable() {
    auto shdrTable = new ShdrTableSection(".shdr_table");
    auto shstrtab = sections->getShStrTab();

    size_t index = 0;
    auto nullSection = new Section("", SHT_NULL);
    auto nullShdr = nullSection->makeShdr(index++, shstrtab->getSize());
    shstrtab->add(nullSection->getName(), true);  // include NULL terminator
    shdrTable->addShdrPair(nullShdr, nullSection);

    for(auto section : sections->getSections()) {
        if(section->hasShdr()) {
            auto shdr = section->makeShdr(index++, shstrtab->getSize());
            shstrtab->add(section->getName(), true);  // include NULL terminator
            shdrTable->addShdrPair(shdr, section);
        }
    }

    sections->addSection(shdrTable);
}

void ObjGen::updateOffsetAndAddress() {
    size_t offset = 0;
    for(auto section : sections->getSections()) {
        section->setOffset(offset);
        offset += section->getSize();
    }
}

void ObjGen::updateShdrTable() {
    ShdrTableSection *shdrTable = static_cast<ShdrTableSection *>(sections->findSection(".shdr_table"));
    for(auto shdrPair : shdrTable->getShdrPairs()) {
        shdrPair.first->sh_offset = shdrPair.second->getOffset();
        shdrPair.first->sh_addr = shdrPair.second->getAddress();
        shdrPair.first->sh_link = shdrTable->findIndex(shdrPair.second->getSectionLink());
        shdrTable->add(shdrPair.first, sizeof(ElfXX_Shdr));
    }
}

void ObjGen::updateHeader() {
    ElfXX_Ehdr *header = sections->getHeader()->castAs<ElfXX_Ehdr>();
    ShdrTableSection *shdrTable = static_cast<ShdrTableSection *>(sections->findSection(".shdr_table"));
    header->e_shoff = shdrTable->getOffset();
    header->e_shnum = shdrTable->getSize() / sizeof(ElfXX_Shdr);
    header->e_shstrndx = shdrTable->findIndex(sections->findSection(".shstrtab"));
}

void ObjGen::serialize() {
    std::ofstream fs(filename, std::ios::out | std::ios::binary);
    for(auto section : sections->getSections()) {
        LOG(1, "serializing " << section->getName() << " @ " << section->getOffset());
        fs << *section;
    }
    fs.close();
}
