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

    //auto header = new Section2(".elfheader", new DeferredValueImpl<ElfXX_Ehdr>());
    //auto strtab = new Section2(".strtab", SHT_STRTAB);
    //auto shstrtab = new Section2(".shstrtab", SHT_STRTAB);
    //auto symtab = new SymbolTableSection(".symtab", SHT_SYMTAB);
    //sectionList.addSection(header);
    //sectionList.addSection(strtab);
    //sectionList.addSection(shstrtab);
    //sectionList.addSection(symtab);
}

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

    // The first data in the elfMap contains the elf header.
    // Make a mutable copy for our own use.
    auto header = new ElfXX_Ehdr(
        *reinterpret_cast<ElfXX_Ehdr *>(elfMap->getMap()));
    auto deferred = new DeferredValueImpl<ElfXX_Ehdr>(header);

    header->e_type = ET_REL;  // object file
    header->e_entry = 0;
    header->e_phoff = 0;
    header->e_phentsize = 0;
    header->e_phnum = 0;

    deferred->addFunction([this] (ElfXX_Ehdr *header) {
        ShdrTableSection *shdrTable = static_cast<ShdrTableSection *>(sectionList[".shdr_table"]);
        header->e_shoff = shdrTable->getHeader()->getOffset();
        header->e_shnum = shdrTable->getContent()->getCount();
    });

    deferred->addFunction([this] (ElfXX_Ehdr *header) {
        header->e_shstrndx = sectionList.indexOf(".shstrtab");
    });

    sectionList.addSection(new Section2(".elfheader", deferred));
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

    Section2 *lastTextSection = nullptr;
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
        auto textSection = new Section2(sectionName.str().c_str(), SHT_PROGBITS,
            SHF_ALLOC | SHF_EXECINSTR);
        textSection->add((const uint8_t *)*i, size);
        sectionList.addTextSection(textSection);

        lastTextSection = textSection;

        totalSize += size;
        i = j;
    }

    // Redo Relocations
    auto symtab = static_cast<SymbolTableSection *>(sectionList[".symtab"]);
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
    sectionList.addSection(relaTextSection);
}

void ObjGen::makeSymbolInfo() {
    auto symtab = static_cast<SymbolTableSection *>(sectionList[".symtab"]);
    auto strtab = sectionList[".strtab"];

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
    auto roDataSection = new Section2(".rodata", SHT_PROGBITS, SHF_ALLOC);
    char *address = elfMap->getCharmap() + oldRoDataShdr->sh_offset;
    roDataSection->add(address, oldRoDataShdr->sh_size);
    sectionList.addSection(roDataSection);
}

void ObjGen::makeShdrTable() {
    auto shdrTable = new ShdrTableSection(".shdr_table");
    auto shstrtab = sectionList[".shstrtab"];

    size_t index = 0;
    auto nullSection = new Section2("", SHT_NULL);
    auto nullShdr = nullSection->makeShdr(index++, shstrtab->getSize());
    shstrtab->add(nullSection->getName(), true);  // include NULL terminator
    shdrTable->addShdrPair(nullSection, nullShdr);

    for(auto section : sectionList) {
        if(section->hasShdr()) {
            auto shdr = section->makeShdr(index++, shstrtab->getSize());
            shstrtab->add(section->getName(), true);  // include NULL terminator
            shdrTable->addShdrPair(section, shdr);
        }
    }

    sectionList.addSection(shdrTable);
}

void ObjGen::updateOffsetAndAddress() {
    size_t offset = 0;
    for(auto section : sectionList) {
        section->setOffset(offset);
        offset += section->getSize();
    }
}

void ObjGen::updateSymbolTable() {
    // update section indices in symbol table
    auto shdrTable = static_cast<ShdrTableSection *>(sectionList[".shdr_table"]);
    auto symtab = static_cast<SymbolTableSection *>(sectionList[".symtab"]);
    auto text = sectionList.getText();
    auto textIndex = shdrTable->findIndex(text);

    for(auto symbol : symtab->getKeyList()) {
        symtab->findValue(symbol)->st_shndx = textIndex;
    }

    for(auto shdrPair : shdrTable->getValueMap()) {
        if(shdrPair.second->sh_type == SHT_NULL)
            continue;
        auto type = Symbol::typeFromElfToInternal(STT_SECTION);
        auto bind = Symbol::bindFromElfToInternal(STB_LOCAL);
        Symbol *sym = new Symbol(0, 0, "", type, bind, 0,
            shdrTable->findIndex(shdrPair.first));
        symtab->add(sym);
    }

}

void ObjGen::updateRelocations() {
    auto symtab = static_cast<SymbolTableSection *>(sectionList[".symbtab"]);
    auto shdrTable = static_cast<ShdrTableSection *>(sectionList[".shdr_table"]);
    auto *relaTextSection = static_cast<RelocationSection *>(sectionList[".rela.text.0x40000000"]);
    for(auto rela : relaTextSection->getValueList()) {
        auto destSection = shdrTable->findIndex(relaTextSection->getDestSection());
        auto index = symtab->findIndexWithShIndex(destSection) + 1;
        LOG(1, "updating rela.rodata " << destSection << " => " << index);
        rela->r_info = ELFXX_R_INFO(index, R_X86_64_PC32);
    }
}

void ObjGen::updateShdrTable() {
    ShdrTableSection *shdrTable = static_cast<ShdrTableSection *>(sectionList[".shdr_table"]);
    for(auto shdrPair : shdrTable->getValueMap()) {
        auto section = shdrPair.first;
        auto shdr    = shdrPair.second;
        shdr->sh_size   = section->getSize();
        shdr->sh_offset = section->getOffset();
        shdr->sh_addr   = section->getAddress();
        shdr->sh_link   = shdrTable->findIndex(section->getSectionLink());
    }
    SymbolTableSection *symtab = static_cast<SymbolTableSection *>(sectionList[".symbtab"]);
    shdrTable->getValueMap()[symtab]->sh_info = shdrTable->getCount();
}

void ObjGen::updateHeader() {
    ElfXX_Ehdr *header = sectionList[".elfheader"]->castAs<ElfXX_Ehdr>();
    ShdrTableSection *shdrTable = static_cast<ShdrTableSection *>(sectionList[".shdr_table"]);
    header->e_shoff = shdrTable->getOffset();
    header->e_shnum = shdrTable->getSize() / sizeof(ElfXX_Shdr);
    LOG(1, "size of section headers is " << shdrTable->getSize() << ", " << sizeof(ElfXX_Shdr));
    header->e_shstrndx = shdrTable->findIndex(sectionList[".shstrtab"]);
}

void ObjGen::serialize() {
    std::ofstream fs(filename, std::ios::out | std::ios::binary);
    for(auto section : sectionList) {
        LOG(1, "serializing " << section->getName()
            << " @ " << std::hex << section->getOffset()
            << " of size " << std::dec << section->getSize());
        fs << *section;
    }
    fs.close();
}

ElfXX_Ehdr *ObjGen::getHeader() {
    return sectionList[".elfheader"]->castAs<ElfXX_Ehdr>();
}
