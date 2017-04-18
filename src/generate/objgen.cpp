#include <set>
#include <cstring>
#include <fstream>
#include <sstream>
#include <elf.h>
#include "objgen.h"
#include "log/registry.h"
#include "log/log.h"


ObjGen::ObjGen(ElfSpace *elfSpace, MemoryBacking *backing, std::string filename) :
    elfSpace(elfSpace), backing(backing), filename(filename) {
    shdrTable = new ShdrTableSection(".shdr_table");
}

void ObjGen::generate() {
    LOG(1, "generating object file");
    makeHeader();
    makeText();
    serialize();
}

void ObjGen::makeHeader() {
    auto elfMap = elfSpace->getElfMap();
    shdrTable->addSection((new Section(".elfheader"))
        ->with(elfMap->getMap(), sizeof(ElfXX_Ehdr)));
    ElfXX_Ehdr *header = shdrTable->findSection(".elfheader")->castAs<ElfXX_Ehdr>();
    header->e_type = ET_REL;
    header->e_entry = 0;
    header->e_phoff = 0;
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
        shdrTable->addSection(textSection);

        totalSize += size;
        i = j;
    }
}

void ObjGen::makeROData() {

}

void ObjGen::makeSymbolInfo() {
    auto symtab = new SymbolTableSection(".symtab", SHT_SYMTAB);
    auto strtab = shdrTable->getStrTab();

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
    shdrTable->addSection(symtab);
    shdrTable->addSection(strtab);
}

void ObjGen::serialize() {
    std::ofstream fs(filename, std::ios::out | std::ios::binary);
    fs << *shdrTable;
    fs.close();
}
