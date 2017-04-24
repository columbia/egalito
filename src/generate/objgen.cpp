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
    text = nullptr;
    sections.push_back(header);
    sections.push_back(strtab);
    sections.push_back(shstrtab);
    sections.push_back(symtab);
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
        auto textSection = new Section(sectionName.str().c_str(), SHT_PROGBITS,
            SHF_ALLOC | SHF_EXECINSTR);
        textSection->add((const uint8_t *)*i, size);
        sections->addTextSection(textSection);

        totalSize += size;
        i = j;
    }
}

void ObjGen::makeSymbolInfo() {
    auto symtab = sections->getSymTab();
    auto strtab = sections->getStrTab();

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
            //continue;  // skip making a symbol for this function
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
    sections->addSection(roDataSection);

    auto symtab = static_cast<SymbolTableSection *>(
        sections->findSection(".symtab"));
    auto relaRoDataSection = new RelocationSection(".rela.rodata", SHT_RELA, SHF_ALLOC);
    relaRoDataSection->setTargetSection(roDataSection);
    relaRoDataSection->setSectionLink(symtab);
    {
        ElfXX_Rela *rela = new ElfXX_Rela();
        rela->r_offset = 0;
        rela->r_info = ELFXX_R_INFO(0, R_X86_64_32S);
        rela->r_addend = 0;
        relaRoDataSection->addRelaPair(roDataSection, rela);
    }
    sections->addSection(relaRoDataSection);
}

void ObjGen::makeShdrTable() {
    auto shdrTable = new ShdrTableSection(".shdr_table");
    auto shstrtab = sections->getShStrTab();

    size_t index = 0;
    auto nullSection = new Section("", SHT_NULL);
    auto nullShdr = nullSection->makeShdr(index++, shstrtab->getSize());
    shstrtab->add(nullSection->getName(), true);  // include NULL terminator
    shdrTable->addShdrPair(nullSection, nullShdr);

    for(auto section : sections->getSections()) {
        if(section->hasShdr()) {
            auto shdr = section->makeShdr(index++, shstrtab->getSize());
            shstrtab->add(section->getName(), true);  // include NULL terminator
            shdrTable->addShdrPair(section, shdr);
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

void ObjGen::updateSymbolTable() {
    // update section indices in symbol table
    auto shdrTable = static_cast<ShdrTableSection *>(
        sections->findSection(".shdr_table"));
    auto strtab = sections->getStrTab();
    auto symtab = sections->getSymTab();
    auto text = sections->getText();
    auto textIndex = shdrTable->findIndex(text);

    for(auto symbol : symtab->getContentList()) {
        symtab->findContent(symbol).st_shndx = textIndex;
    }

    for(auto shdrPair : shdrTable->getContentMap()) {
        if(shdrPair.second->sh_type == SHT_NULL)
            continue;
        ElfXX_Sym symbol;
        symbol.st_name = strtab->add("", 1);
        symbol.st_info = ELFXX_ST_INFO(STB_LOCAL, STT_SECTION);
        symbol.st_other = STV_DEFAULT;
        symbol.st_shndx = shdrTable->findIndex(shdrPair.first);
        symbol.st_value = 0;
        symbol.st_size = 0;
        symtab->add(symbol);
    }
}

void ObjGen::updateRelocations() {
    auto symtab = sections->getSymTab();
    auto shdrTable = static_cast<ShdrTableSection *>(
        sections->findSection(".shdr_table"));
    auto *relaRoDataSection = static_cast<RelocationSection *>(
        sections->findSection(".rela.rodata"));
    for(auto relaPair : relaRoDataSection->getContentMap()) {
        auto index = symtab->findIndexWithShIndex(shdrTable->findIndex(relaPair.first)) + 1;
        LOG(1, "updating rela.rodata " << shdrTable->findIndex(relaPair.first));
        relaPair.second->r_info = ELFXX_R_INFO(index, R_X86_64_32S);
    }
}

void ObjGen::updateShdrTable() {
    ShdrTableSection *shdrTable = static_cast<ShdrTableSection *>(sections->findSection(".shdr_table"));
    for(auto shdrPair : shdrTable->getContentMap()) {
        auto section = shdrPair.first;
        auto shdr    = shdrPair.second;
        shdr->sh_size   = section->getSize();
        shdr->sh_offset = section->getOffset();
        shdr->sh_addr   = section->getAddress();
        shdr->sh_link   = shdrTable->findIndex(section->getSectionLink());
    }
}

void ObjGen::updateHeader() {
    ElfXX_Ehdr *header = sections->getHeader()->castAs<ElfXX_Ehdr>();
    ShdrTableSection *shdrTable = static_cast<ShdrTableSection *>(sections->findSection(".shdr_table"));
    header->e_shoff = shdrTable->getOffset();
    header->e_shnum = shdrTable->getSize() / sizeof(ElfXX_Shdr);
    LOG(1, "size of section headers is " << shdrTable->getSize() << ", " << sizeof(ElfXX_Shdr));
    header->e_shstrndx = shdrTable->findIndex(sections->findSection(".shstrtab"));
}

void ObjGen::serialize() {
    std::ofstream fs(filename, std::ios::out | std::ios::binary);
    for(auto section : sections->getSections()) {
        LOG(1, "serializing " << section->getName()
            << " @ " << std::hex << section->getOffset()
            << " of size " << std::dec << section->getSize());
        fs << *section;
    }
    fs.close();
}
