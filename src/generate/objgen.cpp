#include <set>
#include <cstring>
#include <fstream>
#include <elf.h>
#include "objgen.h"
#include "log/registry.h"
#include "log/log.h"
#include "util/streamasstring.h"

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

    auto strtab = new Section2(".strtab", SHT_STRTAB);
    strtab->setContent(new DeferredStringList());
    sectionList.addSection(strtab);
}

void ObjGen::generate() {
    LOG(1, "generating object file");
    makeHeader();
    makeSymbolInfo();
    makeText();
    makeRoData();
    makeShdrTable();
    updateSymbolTable();  // must run after .text & shdrTable are created
    updateRelocations();
    updateOffsetAndAddress();  // must run before updateShdrTable()
    updateShdrTable();
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
        header->e_shoff = shdrTable->getOffset();
        header->e_shnum = shdrTable->getContent()->getCount();
    });
    deferred->addFunction([this] (ElfXX_Ehdr *header) {
        header->e_shstrndx = sectionList.indexOf(".shstrtab");
    });

    sectionList.addSection(new Section2(".elfheader", deferred));
}

void ObjGen::makeText() {
    // Split separate pages into their own LOAD sections.
    // First, find the set of all pages that are used.
    std::set<address_t> pagesUsed;
    for(auto func : CIter::functions(elfSpace->getModule())) {
        address_t start = func->getAddress() & ~0xfff;
        address_t end = ((func->getAddress() + func->getSize()) + 0xfff) & ~0xfff;
        for(address_t page = start; page < end; page += 0x1000) {
            LOG(1, "code uses page " << std::hex << page);
            pagesUsed.insert(page);
        }
    }

    // Next, map any contiguous pages as single sections.
    std::set<address_t>::iterator i = pagesUsed.begin();
    size_t totalSize = 0;
    while(i != pagesUsed.end()) {
        size_t size = 0;
        std::set<address_t>::iterator j = i;
        while(j != pagesUsed.end() && (*j) == (*i) + size) {
            j++;
            size += 0x1000;
        }

        address_t address = *i;

        LOG(1, "map " << std::hex << address << " size " << size);

        std::string name = StreamAsString()
            << ".text.0x" << std::hex << address;
        auto textSection = new Section2(name.c_str(), SHT_PROGBITS,
            SHF_ALLOC | SHF_EXECINSTR);
        auto textValue = new DeferredString(reinterpret_cast<const char *>(*i), size);
        textSection->setContent(textValue);
        sectionList.addSection(textSection);

        makeSymbolInfoForText(address, size, name);

        totalSize += size;
        i = j;
    }

#if 0
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
#endif
}

void ObjGen::makeSymbolInfo() {
    auto symtabValue = new DeferredMap<Symbol *, ElfXX_Sym *>();
    auto symtab = new SymbolTableSection(".symtab", SHT_SYMTAB);
    symtab->setContent(symtabValue);

    auto strtab = sectionList[".strtab"]->castAs<DeferredStringList *>();

    {  // add null symbol
        auto symbol = new ElfXX_Sym();
        symbol->st_name = strtab->add("", 1);  // add empty name
        symbol->st_info = 0;
        symbol->st_other = STV_DEFAULT;
        symbol->st_shndx = 0;
        symbol->st_value = 0;
        symbol->st_size = 0;
        symtab->getContent()->add(nullptr, &symbol);
    }

    // other symbols will be added later

    symtab->getHeader()->setSectionLink(
        new SectionRef(&sectionList, ".strtab"));
}

void ObjGen::makeSymbolInfoForText(address_t begin, size_t size,
    const std::string &textSection) {

    // Add symbols to the symbol list, but only for those functions
    // which fall into the given range [begin, begin+size).

    auto strtab = sectionList[".strtab"]->castAs<DeferredStringList *>();
    auto symtab = sectionList[".symtab"]->castAs<DeferredMap<Symbol *, ElfXX_Sym *> *>();

    for(auto func : CIter::functions(elfSpace->getModule())) {
        if(blacklistedSymbol(func->getName())) {
            continue;  // skip making a symbol for this function
        }

        if(func->getAddress() < begin
            || func->getAddress() + func->getSize() >= begin + size) {
            continue;  // not in this text section
        }

        // fix addresses for objgen (set base to 0)
        func->getPosition()->set(func->getAddress() - backing->getBase());

        // add name to string table
        auto index = strtab->add(func->getName(), true);
        auto value = symtab->add(func, func->getSymbol(), index);
        value->addFunction([this, textSection] (ElfXX_Sym *symbol) {
            symbol->st_shndx = sectionList.indexOf(textSection);
        });

        for(auto alias : func->getSymbol()->getAliases()) {
            // add name to string table
            auto name = std::string(alias->getName());
            auto index = strtab->add(name, true);
            auto value = symtab->add(func, alias, index)
            value->addFunction([this, textSection] (ElfXX_Sym *symbol) {
                symbol->st_shndx = sectionList.indexOf(textSection);
            });
        }

        // undo address fix
        func->getPosition()->set(backing->getBase() + func->getAddress());
    }
}

void ObjGen::makeRoData() {
    auto elfMap = elfSpace->getElfMap();
    auto oldRoDataShdr = elfMap->findSection(".rodata")->getHeader();
    auto roDataSection = new Section2(".rodata", SHT_PROGBITS, SHF_ALLOC);
    const char *address = elfMap->getCharmap() + oldRoDataShdr->sh_offset;
    auto content = new DeferredString(address, oldRoDataShdr->sh_size);
    roDataSection->setContent(content);
    sectionList.addSection(roDataSection);
}

void ObjGen::makeShdrTable() {
    auto shdrTableValue = new DeferredMap<Section2 *, ElfXX_Shdr *>();
    auto shdrTable = new Section2(".shdr_table");
    shdrTable->setContent(shdrTableValue);

    auto shstrtab = sectionList[".shstrtab"]->castAs<DeferredStringList *>();

    auto nullSection = new Section2("", static_cast<ElfXX_Word>(SHT_NULL));
    makeShdrStructure(nullSection, shdrTableValue);
    shstrtab->add(nullSection->getName(), true);  // include NULL terminator

    for(auto section : sectionList) {
        if(section->hasHeader()) {
            makeShdrStructure(section, shdrTableValue);
            shstrtab->add(section->getName(), true);  // include NULL terminator
        }
    }

    sectionList.addSection(shdrTable);
}

DeferredValueImpl<ElfXX_Shdr> *ObjGen::makeShdrStructure(Section2 *section,
    DeferredMap<Section2 *, ElfXX_Shdr *> *shdrTable) {

    auto shdr = new ElfXX_Shdr();
    std::memset(shdr, 0, sizeof(*shdr));

    auto deferred = new DeferredValueImpl<ElfXX_Shdr>(shdr);

    deferred->addFunction([this, section] (ElfXX_Shdr *shdr) {
        auto header = section->getHeader();
        shdr->sh_name       = 0;
        shdr->sh_type       = header->getShdrType();
        shdr->sh_flags      = header->getShdrFlags();
        shdr->sh_addr       = header->getAddress();
        shdr->sh_offset     = section->getOffset();
        shdr->sh_size       = section->getContent()->getSize();
        shdr->sh_link       = header->getSectionLink()
            ? header->getSectionLink()->getIndex() : 0;
        shdr->sh_info       = 0;  // updated later for strtabs
        shdr->sh_addralign  = 1;
        shdr->sh_entsize    = 0;
    });

    shdrTable->add(section, deferred);
    return deferred;
}

void ObjGen::updateOffsetAndAddress() {
    // every section is written to the file, even those without Headers
    size_t offset = 0;
    for(auto section : sectionList) {
        section->setOffset(offset);
        offset += section->getContent()->getSize();
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

bool ObjGen::blacklistedSymbol(const std::string &name) {
    static bool initialized = false;
    static std::set<std::string> blacklist;

    if(!initialized) {
        // Remove these symbols which are only in executables and will be added
        // back in by the linker.
        blacklist.insert("_init");
        blacklist.insert("_fini");
        blacklist.insert("register_tm_clones");
        blacklist.insert("deregister_tm_clones");
        blacklist.insert("frame_dummy");
        blacklist.insert("__do_global_dtors_aux");
        blacklist.insert("__libc_csu_init");
        blacklist.insert("__libc_csu_fini");
        blacklist.insert("_start");
        initialized = true;
    }

    return blacklist.find(name) != blacklist.end();
}
