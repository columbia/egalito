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
    symtab = new SymbolTableSection(".symtab", SHT_SYMTAB);
    addSection(header);
    addSection(strtab);
    addSection(shstrtab);
    addSection(symtab);
    text = nullptr;
}

ObjGen::Sections::~Sections() {
    for(auto section : sections) {
        delete section;
    }
}

ObjGen::ObjGen(ElfSpace *elfSpace, MemoryBacking *backing, std::string filename) :
    elfSpace(elfSpace), backing(backing), filename(filename) {}

void ObjGen::generate() {
    LOG(1, "generating object file");
    makeHeader();
    makeText();
    makeSymbolInfo();
    makeRoData();
    makeShdrTable();
    updateSymbolTable();  // must run after .text & shdrTable are created
    updateRelocations();
    updateOffsetAndAddress();  // must run before updateShdrTable()
    updateShdrTable();
    updateHeader();
    serialize();
}

void ObjGen::makeHeader() {
    auto elfMap = elfSpace->getElfMap();
    sections[".elfheader"]->add(elfMap->getMap(), sizeof(ElfXX_Ehdr));

    ElfXX_Ehdr *header = sections[".elfheader"]->castAs<ElfXX_Ehdr>();
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

    Section *lastTextSection = nullptr;
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
        auto textSection = new Section(sectionName.str().c_str(), SHT_PROGBITS,
            SHF_ALLOC | SHF_EXECINSTR);
        textSection->add((const uint8_t *)*i, size);
        sections.addTextSection(textSection);

        lastTextSection = textSection;

        totalSize += size;
        i = j;
    }

    // Redo Relocations
    auto symtab = static_cast<SymbolTableSection *>(sections.getSymTab());
    auto relaTextSection = new RelocationSection(lastTextSection);
    relaTextSection->setSectionLink(symtab);
    {
        ElfXX_Rela *rela = new ElfXX_Rela();
        rela->r_offset = 0x1a9;
        rela->r_info = ELFXX_R_INFO(0, 0);
        rela->r_addend = -1;
        relaTextSection->addRela(rela);
    }
    {
        ElfXX_Rela *rela = new ElfXX_Rela();
        rela->r_offset = 0x1c6;
        rela->r_info = ELFXX_R_INFO(0, 0);
        rela->r_addend = 0;
        relaTextSection->addRela(rela);
    }
    sections.addSection(relaTextSection);
}

void ObjGen::makeSymbolInfo() {
    auto symtab = static_cast<SymbolTableSection *>(sections[".symtab"]);
    auto strtab = sections[".strtab"];

    {  // add null symbol
        ElfXX_Sym symbol;
        symbol.st_name = strtab->add("", 1);  // add empty name
        symbol.st_info = 0;
        symbol.st_other = STV_DEFAULT;
        symbol.st_shndx = 0;
        symbol.st_value = 0;
        symbol.st_size = 0;
        symtab->add(static_cast<void *>(&symbol), sizeof(symbol));
    }

    // Remove these symbols which are only in executables and will be added
    // back in by the linker.
    std::set<std::string> blacklist;
    blacklist.insert("_init");
    blacklist.insert("_fini");
    blacklist.insert("register_tm_clones");
    blacklist.insert("deregister_tm_clones");
    blacklist.insert("frame_dummy");
    blacklist.insert("__do_global_dtors_aux");
    blacklist.insert("__libc_csu_init");
    blacklist.insert("__libc_csu_fini");
    blacklist.insert("_start");

    for(auto func : CIter::functions(elfSpace->getModule())) {
        if(blacklist.find(func->getName()) != blacklist.end()) {
            continue;  // skip making a symbol for this function
        }

        // fix addresses for objgen
        func->getPosition()->set(func->getAddress() - backing->getBase());

        // add name to string table
        auto index = strtab->add(func->getName(), true);
        symtab->add(func, func->getSymbol(), index);

        for(auto alias : func->getSymbol()->getAliases()) {
            // add name to string table
            auto name = std::string(alias->getName());
            auto index = strtab->add(name, true);
            symtab->add(func, alias, index);
        }

        // undo address fix
        func->getPosition()->set(backing->getBase() + func->getAddress());
    }

    symtab->setSectionLink(strtab);
}

void ObjGen::makeRoData() {
    auto elfMap = elfSpace->getElfMap();
    auto oldRoDataShdr = elfMap->findSection(".rodata")->getHeader();
    auto roDataSection = new Section(".rodata", SHT_PROGBITS, SHF_ALLOC);
    char *address = elfMap->getCharmap() + oldRoDataShdr->sh_offset;
    roDataSection->add(address, oldRoDataShdr->sh_size);
    sections.addSection(roDataSection);
}

void ObjGen::makeShdrTable() {
    auto shdrTable = new ShdrTableSection(".shdr_table");
    auto shstrtab = sections[".shstrtab"];

    size_t index = 0;
    auto nullSection = new Section("", SHT_NULL);
    auto nullShdr = nullSection->makeShdr(index++, shstrtab->getSize());
    shstrtab->add(nullSection->getName(), true);  // include NULL terminator
    shdrTable->addShdrPair(nullSection, nullShdr);

    for(auto section : sections) {
        if(section->hasShdr()) {
            auto shdr = section->makeShdr(index++, shstrtab->getSize());
            shstrtab->add(section->getName(), true);  // include NULL terminator
            shdrTable->addShdrPair(section, shdr);
        }
    }

    sections.addSection(shdrTable);
}

void ObjGen::updateOffsetAndAddress() {
    size_t offset = 0;
    for(auto section : sections) {
        section->setOffset(offset);
        offset += section->getSize();
    }
}

void ObjGen::updateSymbolTable() {
    // update section indices in symbol table
    auto shdrTable = static_cast<ShdrTableSection *>(sections[".shdr_table"]);
    auto symtab = static_cast<SymbolTableSection *>(sections[".symtab"]);
    auto text = sections.getText();
    auto textIndex = shdrTable->findIndex(text);

    for(auto symbol : symtab->getKeyList()) {
        symtab->findValue(symbol)->st_shndx = textIndex;
    }

    LOG(1, "FIND shindex 5 => " << symtab->findIndexWithShIndex(5));

    for(auto shdrPair : shdrTable->getValueMap()) {
        if(shdrPair.second->sh_type == SHT_NULL)
            continue;
        auto type = Symbol::typeFromElfToInternal(STT_SECTION);
        auto bind = Symbol::bindFromElfToInternal(STB_LOCAL);
        Symbol *sym = new Symbol(0, 0, "", type, bind, 0,
            shdrTable->findIndex(shdrPair.first));
        symtab->add(sym);
    }

    LOG(1, "FIND shindex 5 => " << symtab->findIndexWithShIndex(5));
}

void ObjGen::updateRelocations() {
    auto symtab = sections.getSymTab();
    auto shdrTable = static_cast<ShdrTableSection *>(sections[".shdr_table"]);
    auto *relaTextSection = static_cast<RelocationSection *>(sections[".rela.text.0x40000000"]);
    for(auto rela : relaTextSection->getValueList()) {
        auto destSection = shdrTable->findIndex(relaTextSection->getDestSection());
        auto index = symtab->findIndexWithShIndex(destSection) + 1;
        LOG(1, "updating rela.rodata " << destSection << " => " << index);
        rela->r_info = ELFXX_R_INFO(index, R_X86_64_PC32);
    }
}

void ObjGen::updateShdrTable() {
    ShdrTableSection *shdrTable = static_cast<ShdrTableSection *>(sections[".shdr_table"]);
    for(auto shdrPair : shdrTable->getValueMap()) {
        auto section = shdrPair.first;
        auto shdr    = shdrPair.second;
        shdr->sh_size   = section->getSize();
        shdr->sh_offset = section->getOffset();
        shdr->sh_addr   = section->getAddress();
        shdr->sh_link   = shdrTable->findIndex(section->getSectionLink());
    }
    SymbolTableSection *symtab = sections.getSymTab();
    shdrTable->getValueMap()[symtab]->sh_info = shdrTable->getCount();
}

void ObjGen::updateHeader() {
    ElfXX_Ehdr *header = sections[".elfheader"]->castAs<ElfXX_Ehdr>();
    ShdrTableSection *shdrTable = static_cast<ShdrTableSection *>(sections[".shdr_table"]);
    header->e_shoff = shdrTable->getOffset();
    header->e_shnum = shdrTable->getSize() / sizeof(ElfXX_Shdr);
    LOG(1, "size of section headers is " << shdrTable->getSize() << ", " << sizeof(ElfXX_Shdr));
    header->e_shstrndx = shdrTable->findIndex(sections[".shstrtab"]);
}

void ObjGen::serialize() {
    std::ofstream fs(filename, std::ios::out | std::ios::binary);
    for(auto section : sections) {
        LOG(1, "serializing " << section->getName()
            << " @ " << std::hex << section->getOffset()
            << " of size " << std::dec << section->getSize());
        fs << *section;
    }
    fs.close();
}
