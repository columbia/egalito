#include <set>
#include <fstream>
#include <string.h>
#include "anygen.h"
#include "concretedeferred.h"
#include "transform/sandbox.h"
#include "chunk/concrete.h"
#include "instr/concrete.h"
#include "util/streamasstring.h"
#include "log/log.h"

AnyGen::AnyGen(Module *module, MemoryBacking *backing)
    : module(module), backing(backing) {

    auto header = new Section("=elfheader");
    sectionList.addSection(header);

    auto strtab = new Section(".strtab", SHT_STRTAB);
    strtab->setContent(new DeferredStringList());
    sectionList.addSection(strtab);

    auto shstrtab = new Section(".shstrtab", SHT_STRTAB);
    shstrtab->setContent(new DeferredStringList());
    sectionList.addSection(shstrtab);
}

void AnyGen::generate(const std::string &filename) {
    makeHeader();
    makePhdrTable();  // can add phdrs after this
    makeSymtabSection();
    makeDataSections();
    makeText();
    makeShdrTable();  // don't create new shdrs after this
    updateOffsets();  // don't insert any new bytes after this
    serialize(filename);
}

void AnyGen::makeHeader() {
    // Generate an ELF header for the current platform.
    auto header = new ElfXX_Ehdr();
    auto deferred = new DeferredValueImpl<ElfXX_Ehdr>(header);

    // set up e_ident field
    memset(header->e_ident, 0, EI_NIDENT);
    strncpy(reinterpret_cast<char *>(header->e_ident), ELFMAG, SELFMAG);
    header->e_ident[EI_CLASS] = ELFCLASS64;
#ifdef ARCH_X86_64
    header->e_ident[EI_DATA] = ELFDATA2LSB;
#else
    header->e_ident[EI_DATA] = ELFDATA2MSB;
#endif
    header->e_ident[EI_VERSION] = EV_CURRENT;
    header->e_ident[EI_OSABI] = ELFOSABI_NONE;
    header->e_ident[EI_ABIVERSION] = 0;

    // set up other typical ELF fields
    header->e_type = ET_EXEC;
#ifdef ARCH_X86_64
    header->e_machine = EM_X86_64;
#else
    header->e_machine = EM_AARCH64;
#endif
    header->e_version = EV_CURRENT;
    header->e_flags = 0;

    header->e_ehsize = sizeof(ElfXX_Ehdr);
    header->e_phentsize = sizeof(ElfXX_Phdr);
    header->e_shentsize = sizeof(ElfXX_Shdr);

    deferred->addFunction([this] (ElfXX_Ehdr *header) {
        auto shdrTableSection = sectionList["=shdr_table"];
        auto shdrTable = shdrTableSection->castAs<ShdrTableContent *>();
        header->e_shoff = shdrTableSection->getOffset();
        header->e_shnum = shdrTable->getCount();
    });
    deferred->addFunction([this] (ElfXX_Ehdr *header) {
        auto phdrTableSection = sectionList["=phdr_table"];
        auto phdrTable = phdrTableSection->castAs<PhdrTableContent *>();
        header->e_phoff = phdrTableSection->getOffset();
        header->e_phnum = phdrTable->getCount();
    });
    deferred->addFunction([this] (ElfXX_Ehdr *header) {
        header->e_shstrndx = shdrIndexOf(".shstrtab");
    });

    if(auto program = dynamic_cast<Program *>(module->getParent())) {
        if(module == program->getMain()) {
            header->e_entry = program->getEntryPointAddress();
        }
    }

    sectionList["=elfheader"]->setContent(deferred);
}

void AnyGen::makeSymtabSection() {
    auto strtab = sectionList[".strtab"]->castAs<DeferredStringList *>();

    auto symtab = new SymbolTableContent(strtab);
    auto symtabSection = new Section(".symtab", SHT_SYMTAB);
    symtabSection->setContent(symtab);

    symtab->addNullSymbol();
    // other symbols will be added later

    symtabSection->getHeader()->setSectionLink(
        new SectionRef(&sectionList, ".strtab"));
    sectionList.addSection(symtabSection);
}

void AnyGen::makeShdrTable() {
    LOG(1, "generating shdr table");
    auto shdrTable = new ShdrTableContent();
    auto shdrTableSection = new Section("=shdr_table", shdrTable);

    auto shstrtab = sectionList[".shstrtab"]->castAs<DeferredStringList *>();

    auto nullSection = new Section("", static_cast<ElfXX_Word>(SHT_NULL));
    auto nullDeferred = shdrTable->add(nullSection);
    nullDeferred->getElfPtr()->sh_name
        = shstrtab->add(nullSection->getName(), true);

    for(auto section : sectionList) {
        if(section->hasHeader()) {
            auto deferred = shdrTable->add(section);
            deferred->getElfPtr()->sh_name
                = shstrtab->add(section->getName(), true);

            if(dynamic_cast<SymbolTableContent *>(section->getContent())) {
                deferred->addFunction([this, shdrTable] (ElfXX_Shdr *shdr) {
                    auto symtab = sectionList[".symtab"]->castAs<SymbolTableContent *>();
                    shdr->sh_info = symtab->getFirstGlobalIndex();
                    shdr->sh_entsize = sizeof(ElfXX_Sym);
                    shdr->sh_addralign = 8;
                });
            }
            else if(auto v = dynamic_cast<RelocSectionContent2 *>(section->getContent())) {
                deferred->addFunction([this, v] (ElfXX_Shdr *shdr) {
                    shdr->sh_info = shdrIndexOf(v->getTargetSection());
                    shdr->sh_addralign = 8;
                    shdr->sh_entsize = sizeof(ElfXX_Rela);
                    shdr->sh_link = shdrIndexOf(".symtab");
                });
            }
        }
    }

    sectionList.addSection(shdrTableSection);
}

void AnyGen::makePhdrTable() {
    LOG(1, "generating phdr table");
    auto phdrTable = new PhdrTableContent(&sectionList);
    auto phdrTableSection = new Section("=phdr_table", phdrTable);
    sectionList.addSection(phdrTableSection);

    auto phdr = new SegmentInfo(PT_PHDR, PF_R | PF_X, 0x8);
    phdr->addContains(sectionList["=elfheader"]);
    phdrTable->add(phdr);

#if 0
    auto interpSection = new Section(".interp", SHT_PROGBITS, 0);
    const char *interpreter = "/lib64/ld-linux-x86-64.so.2";
    auto interpContent = new DeferredString(interpreter, strlen(interpreter) + 1);
    interpSection->setContent(interpContent);
    sectionList.addSection(interpSection);
    auto interp = new SegmentInfo(PT_INTERP, PF_R, 0x1);
    interp->addContains(interpSection);
    phdrTable->add(interp);
#endif
}

void AnyGen::makeDataSections() {
    // Before all LOAD segments, we need to put padding.
    makePaddingSection(0);

    auto phdrTable = sectionList["=phdr_table"]->castAs<PhdrTableContent *>();
    auto regionList = module->getDataRegionList();
    for(auto region : CIter::children(regionList)) {
        auto loadSegment = new SegmentInfo(PT_LOAD, PF_R | PF_W, 0x1000);

        for(auto section : CIter::children(region)) {
            switch(section->getType()) {
            case DataSection::TYPE_DATA: {
                LOG(0, "DATA section " << section->getName());
                makePaddingSection(section->getAddress() & 0xfff);

                // by default, make everything writable
                auto dataSection = new Section(section->getName(),
                    SHT_PROGBITS, SHF_ALLOC | SHF_WRITE);
                auto content = new DeferredString(region->getDataBytes()
                    .substr(section->getOriginalOffset(), section->getSize()));
                dataSection->setContent(content);
                dataSection->getHeader()->setAddress(section->getAddress());
                sectionList.addSection(dataSection);
                loadSegment->addContains(dataSection);
                break;
            }
            case DataSection::TYPE_BSS: {
                LOG(0, "BSS section " << section->getName());
                makePaddingSection(section->getAddress() & 0xfff);

                auto bssSection = new Section(section->getName(),
                    SHT_NOBITS, SHF_ALLOC | SHF_WRITE);
                bssSection->setContent(new DeferredString(""));
                bssSection->getHeader()->setAddress(section->getAddress());
                sectionList.addSection(bssSection);
                loadSegment->addContains(bssSection);
                break;
            }
            case DataSection::TYPE_UNKNOWN:
            default:
                break;
            }
        }

        if(loadSegment->getContainsList().empty()) {
            delete loadSegment;
        }
        else {
            phdrTable->add(loadSegment);
        }
    }
}

void AnyGen::makeText() {
    // Before all LOAD segments, we need to put padding.
    makePaddingSection(0);

    // Split separate pages into their own LOAD sections.
    // First, find the set of all pages that are used.
    std::set<address_t> pagesUsed;
    for(auto func : CIter::functions(module)) {
        address_t start = func->getAddress() & ~0xfff;
        address_t end = ((func->getAddress() + func->getSize()) + 0xfff) & ~0xfff;
        for(address_t page = start; page < end; page += 0x1000) {
            LOG(19, "code uses page " << std::hex << page);
            pagesUsed.insert(page);
        }
    }

    // Next, find sequences of contiguous pages and merge them.
    std::vector<Range> codeRegions;
    std::set<address_t>::iterator i = pagesUsed.begin();
    while(i != pagesUsed.end()) {
        size_t size = 0;
        std::set<address_t>::iterator j = i;
        while(j != pagesUsed.end() && (*j) == (*i) + size) {
            j++;
            size += 0x1000;
        }

        address_t address = *i;
        codeRegions.push_back(Range(address, size));
        i = j;
    }

    // Finally, map all code regions as individual ELF segments.
    auto phdrTable = sectionList["=phdr_table"]->castAs<PhdrTableContent *>();
    for(auto range : codeRegions) {
        auto address = range.getStart();
        auto size = range.getSize();
        LOG(1, "map " << std::hex << address << " size " << size);

        std::string name;
        if(codeRegions.size() == 1) name = ".text";
        else {
            name = StreamAsString() << ".text.0x" << std::hex << address;
        }
        auto textSection = new Section(name.c_str(), SHT_PROGBITS,
            SHF_ALLOC | SHF_EXECINSTR);
        auto textValue = new DeferredString(
            reinterpret_cast<const char *>(address), size);
        textSection->getHeader()->setAddress(address);
        textSection->setContent(textValue);
        sectionList.addSection(textSection);

        makeRelocSectionFor(name);
        makeSymbolsAndRelocs(address, size, name);

        auto loadSegment = new SegmentInfo(PT_LOAD, PF_R | PF_X, 0x1000);
        loadSegment->addContains(textSection);
        phdrTable->add(loadSegment);
    }
}

void AnyGen::makeRelocSectionFor(const std::string &otherName) {
    auto reloc = new RelocSectionContent2(
        new SectionRef(&sectionList, otherName));
    auto relocSection = new Section(".rela" + otherName, SHT_RELA, SHF_INFO_LINK);
    relocSection->setContent(reloc);

    sectionList.addSection(relocSection);
}

void AnyGen::makeSymbolsAndRelocs(address_t begin, size_t size,
    const std::string &textSection) {

    // Add symbols to the symbol list, but only for those functions
    // which fall into the given range [begin, begin+size).
    for(auto func : CIter::functions(module)) {
        if(blacklistedSymbol(func->getName())) {
            continue;  // skip making a symbol for this function
        }

        if(func->getAddress() < begin
            || func->getAddress() + func->getSize() >= begin + size) {
            continue;  // not in this text section
        }

        // fix addresses for objgen (set base to 0)
        ////func->getPosition()->set(func->getAddress() - backing->getBase());

        LOG(1, "making symbol for " << func->getName());
        makeSymbolInText(func, textSection);
        makeRelocInText(func, textSection);

        // undo address fix
        ////func->getPosition()->set(backing->getBase() + func->getAddress());
    }

#if 0
    // Handle any other types of symbols that need generating.
    for(auto sym : *elfSpace->getSymbolList()) {
        if(sym->isFunction()) continue;  // already handled
        if(blacklistedSymbol(sym->getName())) continue;  // blacklisted

        // undefined symbol
        if(sym->getSectionIndex() == SHN_UNDEF) {
            auto symtab = sectionList[".symtab"]->castAs<SymbolTableContent *>();
            symtab->addUndefinedSymbol(sym);
        }
    }
#endif
}

void AnyGen::makeSymbolInText(Function *func, const std::string &textSection) {
    auto symtab = sectionList[".symtab"]->castAs<SymbolTableContent *>();

    // add name to string table
    auto value = symtab->addSymbol(func, func->getSymbol());
    value->addFunction([this, textSection] (ElfXX_Sym *symbol) {
        symbol->st_shndx = shdrIndexOf(textSection);
    });

    for(auto alias : func->getSymbol()->getAliases()) {
        // skip functions with the same name (due to versioning)
        if(alias->getName() == func->getName()) continue;

        // add name to string table
        auto value = symtab->addSymbol(func, alias);
        value->addFunction([this, textSection] (ElfXX_Sym *symbol) {
            symbol->st_shndx = shdrIndexOf(textSection);
        });
    }

#if 0  // ExternalSymbol can no longer be converted to a Symbol
    for(auto block : CIter::children(func)) {
        for(auto instr : CIter::children(block)) {
            if(auto link = instr->getSemantic()->getLink()) {
                if(auto sol = dynamic_cast<PLTLink *>(link)) {
                    auto sym = sol->getPLTTrampoline()->getTargetSymbol();
                    symtab->addUndefinedSymbol(sym);
                    LOG(1, "undefined symbol with name " << sym->getName());
                }
            }
        }
    }
#endif
}

void AnyGen::makeRelocInText(Function *func, const std::string &textSection) {
    auto reloc = sectionList[".rela" + textSection]->castAs<RelocSectionContent2 *>();

    for(auto block : CIter::children(func)) {
        for(auto instr : CIter::children(block)) {
            if(auto link = instr->getSemantic()->getLink()) {
                LOG(1, "SKIP adding relocation at " << instr->getName());
                //reloc->add(instr, link);
            }
        }
    }
}

void AnyGen::makePaddingSection(size_t desiredAlignment) {
    // We could assign unique names to the padding sections, but since we
    // never look them up by name in SectionList, it doesn't actually matter.
    auto paddingSection = new Section("=padding");
    auto paddingContent = new PagePaddingContent(
        sectionList.back(), desiredAlignment);
    paddingSection->setContent(paddingContent);
    sectionList.addSection(paddingSection);
}

void AnyGen::updateOffsets() {
    // every Section is written to the file, even those without SectionHeaders
    size_t offset = 0;
    for(auto section : sectionList) {
        LOG(1, "section [" << section->getName() << "] is at offset " << std::dec << offset);
        section->setOffset(offset);
        offset += section->getContent()->getSize();
    }
}

void AnyGen::serialize(const std::string &filename) {
    std::ofstream fs(filename, std::ios::out | std::ios::binary);
    for(auto section : sectionList) {
        LOG(1, "serializing " << section->getName()
            << " @ " << std::hex << section->getOffset()
            << " of size " << std::dec << section->getContent()->getSize());
        fs << *section;
    }
    fs.close();
}

size_t AnyGen::shdrIndexOf(Section *section) {
#if 0
    auto shdrTableSection = sectionList["=shdr_table"];
    auto shdrTable = shdrTableSection->castAs<ShdrTableContent *>();
    return shdrTable->indexOf(shdrTable->find(section));
#else
    return sectionList.indexOf(section);
#endif
}

size_t AnyGen::shdrIndexOf(const std::string &name) {
#if 0
    auto shdrTableSection = sectionList["=shdr_table"];
    auto shdrTable = shdrTableSection->castAs<ShdrTableContent *>();
    return shdrTable->indexOf(shdrTable->find(sectionList[name]));
#else
    return sectionList.indexOf(name);
#endif
}

bool AnyGen::blacklistedSymbol(const std::string &name) {
    return false;
}
