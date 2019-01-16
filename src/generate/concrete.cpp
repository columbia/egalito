#include <cstring>
#include <fstream>
#include <sys/stat.h>
#include "concrete.h"
#include "modulegen.h"
#include "sectionlist.h"
#include "concretedeferred.h"
#include "transform/sandbox.h"
#include "chunk/concrete.h"
#include "operation/find2.h"
#include "elf/elfspace.h"
#include "elf/symbol.h"
#include "instr/concrete.h"
#include "util/streamasstring.h"
#include "log/log.h"
#include "config.h"

void BasicElfCreator::execute() {
    auto header = new Section("=elfheader");
    getSectionList()->addSection(header);

    auto interpSection = new Section(".interp", SHT_PROGBITS, 0);
    getSectionList()->addSection(interpSection);
    
    if (makeInitArray) {
        auto initArraySection = new Section(".init_array", SHT_INIT_ARRAY,
            SHF_WRITE | SHF_ALLOC);
        getSectionList()->addSection(initArraySection);
    }

    auto phdrTable = new PhdrTableContent(getSectionList());
    auto phdrTableSection = new Section("=phdr_table", phdrTable);
    getSectionList()->addSection(phdrTableSection);

    auto strtab = new Section(".strtab", SHT_STRTAB);
    auto strtabContent = new DeferredStringList();
    strtab->setContent(strtabContent);
    getSectionList()->addSection(strtab);

    auto shstrtab = new Section(".shstrtab", SHT_STRTAB);
    shstrtab->setContent(new DeferredStringList());
    getSectionList()->addSection(shstrtab);

    if(getConfig()->isDynamicallyLinked()) {
        ModuleGen(ModuleGen::Config(), nullptr, getSectionList())
            .makePaddingSection(0);
        auto dynstr = new Section(".dynstr", SHT_STRTAB);
        auto stringList = new DeferredStringList();
        stringList->add("123456", true);
        dynstr->setContent(stringList);
        getSectionList()->addSection(dynstr);

        // symtab
        auto symtab = new SymbolTableContent(strtabContent);
        auto symtabSection = new Section(".symtab", SHT_SYMTAB);
        symtabSection->setContent(symtab);
        symtab->addNullSymbol();
        // other symbols will be added later
        getSectionList()->addSection(symtabSection);

        auto dynsym = new SymbolTableContent(stringList);
        auto dynsymSection = new Section(".dynsym", SHT_DYNSYM);
        //auto dynsymSection = getSection(".dynsym");
        dynsymSection->setContent(dynsym);
        dynsym->addNullSymbol();
        // other symbols will be added later
        getSectionList()->addSection(dynsymSection);

        // .rela.dyn
        auto relaDyn = new DataRelocSectionContent(
            nullptr /*new SectionRef(&sectionList, ".dynsym")*/,
            getSectionList());
        auto relaDynSection = new Section(".rela.dyn", SHT_RELA);
        relaDynSection->setContent(relaDyn);
        getSectionList()->addSection(relaDynSection);
        // .dynamic

        auto dynamicSection = new Section(".dynamic", SHT_DYNAMIC);
        auto dynamic = new DynamicSectionContent();
        dynamicSection->setContent(dynamic);
        getSectionList()->addSection(dynamicSection);

        {
            MakePaddingSection makePadding(0);
            makePadding.setData(getData());
            makePadding.setConfig(getConfig());
            makePadding.execute();
        }

        // note: section contents are set later
        auto gotplt = new Section(".g.got.plt",
            SHT_PROGBITS, SHF_ALLOC | SHF_WRITE);
        getSectionList()->addSection(gotplt);

        auto relaplt = new Section(".rela.plt",
            SHT_RELA, SHF_ALLOC | SHF_INFO_LINK);
        getSectionList()->addSection(relaplt);
    }
}

void BasicElfStructure::execute() {
    makeHeader();
    makePhdrTable();  // can add phdrs after this
    makeSymtabSection();
    if(getConfig()->isDynamicallyLinked()) {
        makeDynamicSection();
    }
}

void BasicElfStructure::makeHeader() {
    // Generate an ELF header for the current platform.
    auto header = new ElfXX_Ehdr();
    auto deferred = new DeferredValueImpl<ElfXX_Ehdr>(header);

    // set up e_ident field
    std::memset(header->e_ident, 0, EI_NIDENT);
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
        auto shdrTableSection = getSection("=shdr_table");
        auto shdrTable = shdrTableSection->castAs<ShdrTableContent *>();
        header->e_shoff = shdrTableSection->getOffset();
        header->e_shnum = shdrTable->getCount();
    });
    deferred->addFunction([this] (ElfXX_Ehdr *header) {
        auto phdrTableSection = getSection("=phdr_table");
        auto phdrTable = phdrTableSection->castAs<PhdrTableContent *>();
        header->e_phoff = phdrTableSection->getOffset();
        header->e_phnum = phdrTable->getCount();
    });
    deferred->addFunction([this] (ElfXX_Ehdr *header) {
        header->e_shstrndx = getSectionList()->indexOf(".shstrtab");
    });

    if(getData()->getProgram()->getEntryPoint()) {
        deferred->addFunction([this] (ElfXX_Ehdr *header) {
            header->e_entry = getData()->getProgram()->getEntryPointAddress();
        });
    } else {
        LOG(1, "No entry point found in program when generating ELF file");
    }

    getSection("=elfheader")->setContent(deferred);
}

void BasicElfStructure::makeSymtabSection() {
    {
        auto strtab = getSection(".strtab")->castAs<DeferredStringList *>();

        #if 0
        auto symtab = new SymbolTableContent(strtab);
        auto symtabSection = new Section(".symtab", SHT_SYMTAB);
        symtabSection->setContent(symtab);

        symtab->addNullSymbol();
        // other symbols will be added later
        #endif

        auto symtabSection = getSection(".symtab");
        symtabSection->getHeader()->setSectionLink(
            new SectionRef(getSectionList(), ".strtab"));
        //getSectionList()->addSection(symtabSection);
    }
    if(getConfig()->isDynamicallyLinked()) {
#if 0
        auto dynstr = getSection(".dynstr")->castAs<DeferredStringList *>();

        auto dynsym = new SymbolTableContent(dynstr);
        //auto dynsymSection = new Section(".dynsym", SHT_DYNSYM);
        auto dynsymSection = getSection(".dynsym");
        dynsymSection->setContent(dynsym);

        dynsym->addNullSymbol();
        // other symbols will be added later
#endif
        auto dynsymSection = getSection(".dynsym");

        dynsymSection->getHeader()->setSectionLink(
            new SectionRef(getSectionList(), ".dynstr"));
        dynsymSection->getHeader()->setShdrFlags(SHF_ALLOC);
        //getSectionList()->addSection(dynsymSection);
    }
}

void GenerateSectionTable::execute() {
    makeShdrTable();
    makeSectionSymbols();
}

void GenerateSectionTable::makeShdrTable() {
    {
        MakePaddingSection makePadding(0);
        makePadding.setData(getData());
        makePadding.setConfig(getConfig());
        makePadding.execute();
    }

    LOG(1, "generating shdr table");
    auto shdrTable = new ShdrTableContent();
    auto shdrTableSection = new Section("=shdr_table", shdrTable);

    auto shstrtab = getSection(".shstrtab")->castAs<DeferredStringList *>();

    auto nullSection = new Section("", static_cast<ElfXX_Word>(SHT_NULL));
    auto nullDeferred = shdrTable->add(nullSection);
    nullDeferred->getElfPtr()->sh_name
        = shstrtab->add(nullSection->getName(), true);

    auto sectionList = getSectionList();
    for(auto section : *sectionList) {
        if(section->hasHeader()) {
            auto deferred = shdrTable->add(section);
            deferred->getElfPtr()->sh_name
                = shstrtab->add(section->getName(), true);

            if(auto symtab = dynamic_cast<SymbolTableContent *>(section->getContent())) {
                deferred->addFunction([symtab] (ElfXX_Shdr *shdr) {
                    //auto symtab = getSection(".symtab")->castAs<SymbolTableContent *>();

                    shdr->sh_info = symtab->getFirstGlobalIndex();
                    shdr->sh_entsize = sizeof(ElfXX_Sym);
                    shdr->sh_addralign = 8;
                });
            }
            else if(auto v = dynamic_cast<RelocSectionContent2 *>(section->getContent())) {
                deferred->addFunction([this, sectionList, v] (ElfXX_Shdr *shdr) {
                    shdr->sh_info = sectionList->indexOf(v->getTargetSection());
                    shdr->sh_addralign = 8;
                    shdr->sh_entsize = sizeof(ElfXX_Rela);
                    shdr->sh_link = sectionList->indexOf(".symtab");
                });
            }
            else if(auto v = dynamic_cast<DataRelocSectionContent *>(section->getContent())) {
                deferred->addFunction([this, sectionList, v] (ElfXX_Shdr *shdr) {
                    shdr->sh_addralign = 8;
                    shdr->sh_entsize = sizeof(ElfXX_Rela);
                    shdr->sh_link = sectionList->indexOf(".dynsym");
                });
            }
        }
    }

    getSectionList()->addSection(shdrTableSection);
}

void GenerateSectionTable::makeSectionSymbols() {
    // update section indices in symbol table
    auto shdrTable = getSection("=shdr_table")->castAs<ShdrTableContent *>();
    auto symtab = getSection(".symtab")->castAs<SymbolTableContent *>();

    // add section symbols
    for(auto shdr : *shdrTable) {
        auto section = shdrTable->getKey(shdr);
        if(!section->getHeader()) continue;
        if(section->getHeader()->getShdrType() == SHT_NULL) continue;

        auto symbol = new Symbol(0, 0, "",
            Symbol::typeFromElfToInternal(STT_SECTION),
            Symbol::bindFromElfToInternal(STB_LOCAL),
            0, getSectionList()->indexOf(section));
        symtab->addSectionSymbol(symbol);
    }
    symtab->recalculateIndices();
}


void BasicElfStructure::makePhdrTable() {
    LOG(1, "generating phdr table");
    auto phdrTable = getSection("=phdr_table")->castAs<PhdrTableContent *>();

    auto phdr = new SegmentInfo(PT_PHDR, PF_R | PF_X, 0x8);
    phdr->addContains(getSection("=phdr_table"));
    auto deferred = phdrTable->add(phdr);
    deferred->addFunction([this] (ElfXX_Phdr *phdr) {
        phdr->p_vaddr = 0x200000 + getSection("=phdr_table")->getOffset();
        phdr->p_paddr = phdr->p_vaddr;
    });

    auto interpSection = getSection(".interp");
#ifndef USE_MUSL
    const char *interpreter = "/lib64/ld-linux-x86-64.so.2";
#else
    const char *interpreter = "/lib/ld-musl-x86_64.so.1";
#endif
    auto interpContent = new DeferredString(interpreter, strlen(interpreter) + 1);
    interpSection->setContent(interpContent);
    auto interp = new SegmentInfo(PT_INTERP, PF_R, 0x1);
    interp->addContains(interpSection);
    auto interpDeferred = phdrTable->add(interp);
    interpDeferred->addFunction([this] (ElfXX_Phdr *phdr) {
        phdr->p_vaddr = 0x200000 + getSection(".interp")->getOffset();
        phdr->p_paddr = phdr->p_vaddr;
    });
}

void BasicElfStructure::makeDynamicSection() {
    #if 0
    {
        MakePaddingSection makePadding(0);
        makePadding.setData(getData());
        makePadding.setConfig(getConfig());
        makePadding.execute();
    }
    #endif

    //auto dynamicSection = new Section(".dynamic", SHT_DYNAMIC);
    //auto dynamic = new DynamicSectionContent();
    auto dynamicSection = getSection(".dynamic");
    auto dynamic = dynamicSection->castAs<DynamicSectionContent *>();

    // Add DT_NEEDED dependency on ld.so because we combine libc into
    // our executable, and libc uses _rtld_global{,_ro} from ld.so.
    auto dynstr = getSection(".dynstr")->castAs<DeferredStringList *>();
    dynamic->addPair(DT_NEEDED,
        dynstr->add("ld-linux-x86-64.so.2", true));

    dynamic->addPair(DT_STRTAB, [this] () {
        auto dynstrSection = getSection(".dynstr");
        return dynstrSection->getHeader()->getAddress();
    });

    dynamic->addPair(DT_SYMTAB, [this] () {
        auto dynsymSection = getSection(".dynsym");
        return dynsymSection->getHeader()->getAddress();
    });

    dynamic->addPair(DT_RELA, [this] () {
        auto relaDyn = getSection(".rela.dyn");
        return relaDyn->getHeader()->getAddress();
    });
    dynamic->addPair(DT_RELASZ, [this] () {
        auto relaDyn = getSection(".rela.dyn");
        return relaDyn->getContent()->getSize();
    });
    dynamic->addPair(DT_RELAENT, sizeof(ElfXX_Rela));

    dynamic->addPair(DT_FLAGS, DF_STATIC_TLS);

    /*
0x0000000000000003 (PLTGOT)             0x200fa0
0x0000000000000002 (PLTRELSZ)           96 (bytes)
0x0000000000000014 (PLTREL)             RELA
   */
    dynamic->addPair(DT_PLTGOT, [this] () {
        auto gotplt = getSection(".g.got.plt");
        return gotplt->getHeader()->getAddress();
    });
    dynamic->addPair(DT_PLTRELSZ, [this] () {
        auto relaplt = getSection(".rela.plt");
        return relaplt->getContent()->getSize();
    });
    dynamic->addPair(DT_PLTREL, DT_RELA);
    dynamic->addPair(DT_JMPREL, [this] () {
        auto relaplt= getSection(".rela.plt");
        return relaplt->getHeader()->getAddress();
    });

    dynamic->addPair(0, 0);

    dynamicSection->setContent(dynamic);
    dynamicSection->getHeader()->setSectionLink(new SectionRef(getSectionList(), ".dynstr"));
    //getSectionList()->addSection(dynamicSection);
}

void AssignSectionsToSegments::execute() {
    auto phdrTable = getSection("=phdr_table")->castAs<PhdrTableContent *>();
    auto loadSegment = new SegmentInfo(PT_LOAD, PF_R | PF_W, 0x200000);
    loadSegment->addContains(getSection("=elfheader"));  // constant size
    loadSegment->addContains(getSection(".interp"));     // constant size
    if(auto s = getSection(".init_array")) loadSegment->addContains(s);
    loadSegment->addContains(getSection("=phdr_table"));
    //loadSegment->addContains(getSection(".strtab"));
    //loadSegment->addContains(getSection(".shstrtab"));
    phdrTable->add(loadSegment, 0x200000);
    phdrTable->assignAddressesToSections(loadSegment, 0x200000);

    if(getConfig()->isDynamicallyLinked()) {
        //auto dynSegment = new SegmentInfo(PT_LOAD, PF_R | PF_W, 0x200000);
        auto dynSegment = new SegmentInfo(PT_LOAD, PF_R | PF_W, /*0x400000*/ 0x1000);
        dynSegment->addContains(getSection(".dynstr"));
        dynSegment->addContains(getSection(".symtab"));
        dynSegment->addContains(getSection(".dynsym"));
        dynSegment->addContains(getSection(".rela.dyn"));
        dynSegment->addContains(getSection(".dynamic"));
        phdrTable->add(dynSegment, 0x400000);

        auto dynSegment2 = new SegmentInfo(PT_LOAD, PF_R | PF_W, /*0x400000*/ 0x1000);
        dynSegment2->addContains(getSection(".g.got.plt"));
        dynSegment2->addContains(getSection(".rela.plt"));
        phdrTable->add(dynSegment2, 0x500000);

        auto pltSegment = new SegmentInfo(PT_LOAD, PF_R | PF_X, 0x1000);
        pltSegment->addContains(getSection(".plt"));
        phdrTable->add(pltSegment, 0x600000);

        auto dynamicSegment = new SegmentInfo(PT_DYNAMIC, PF_R | PF_W, 0x8);
        dynamicSegment->addContains(getSection(".dynamic"));
        phdrTable->add(dynamicSegment);
    }
}

void TextSectionCreator::execute() {
    // this function assumes WatermarkAllocator being used.

    // Before all LOAD segments, we need to put padding.
    MakePaddingSection makePadding(0);
    makePadding.setData(getData());
    makePadding.setConfig(getConfig());
    makePadding.execute();

    auto phdrTable = getSection("=phdr_table")->castAs<PhdrTableContent *>();
    // Finally, map all code regions as individual ELF segments.
    auto address = getData()->getBacking()->getBase();
    //auto size = getData()->getBacking()->getSize();
    auto size = (getData()->getBacking()->getBuffer().length() + 0xfff) & ~0x1000;
    LOG(1, "map " << std::hex << address << " size " << size);


    auto textSection = new Section(".text", SHT_PROGBITS,
        SHF_ALLOC | SHF_EXECINSTR);
    DeferredString *textValue = nullptr;
    // Don't modify backing after this point to avoid invalidating c_str
    auto copy = new std::string(getData()->getBacking()->getBuffer());
    textValue = new DeferredString(
        reinterpret_cast<const char *>(copy->c_str()),
        copy->length());

    if(getConfig()->isFreestandingKernel()) {
        textSection->getHeader()->setAddress(LINUX_KERNEL_CODE_BASE);
    }
    else {
        textSection->getHeader()->setAddress(address);
    }
    textSection->setContent(textValue);

    getSectionList()->addSection(textSection);

    auto loadSegment = new SegmentInfo(PT_LOAD, PF_R | PF_X, 0x1000);
    loadSegment->addContains(textSection);
    phdrTable->add(loadSegment);
}

MakeInitArray::MakeInitArray(int stage) : stage(stage) {
    setName(StreamAsString() << "MakeInitArray{stage=" << stage << "}");
}

void MakeInitArray::execute() {
    if(stage==0) {
        makeInitArraySections();
    } else {
        makeInitArraySectionLinks();
    }
}

void MakeInitArray::makeInitArraySections() {
    /*auto initArraySection = new Section(".init_array", SHT_INIT_ARRAY,
        SHF_WRITE | SHF_ALLOC);*/
    auto initArraySection = getData()->getSection(".init_array");
    auto content = new InitArraySectionContent();

    address_t firstInit = 0;
    std::vector<Link *> initFunctions;
    for(auto module : CIter::children(getData()->getProgram())) {
        for(auto region : CIter::regions(module)) {
            for(auto section : CIter::children(region)) {
                if(section->getType() == DataSection::TYPE_INIT_ARRAY) {
                    LOG(1, "Found init_array section in " << module->getName());
                    for(auto var : CIter::children(section)) {
                        initFunctions.push_back(var->getDest());
                        LOG(0, "Adding init function 0x"
                            << var->getDest()->getTargetAddress()
                            << " to .init_array");
                    }
                }
                if(section->getType() == DataSection::TYPE_DYNAMIC) {
#if 0
                    auto elf = module->getElfSpace()->getElfMap();
                    auto dynamic = elf->getSectionReadPtr<unsigned long *>(".dynamic");
                    for(unsigned long *pointer = dynamic; *pointer != DT_NULL; pointer += 2) {
                        unsigned long type = pointer[0];
                        unsigned long value = pointer[1];

                        if(type == DT_INIT) {
                            initFunctions.push_back;
                        }
                    }
#endif
                    auto bytes = region->getDataBytes();
                    auto p = reinterpret_cast<const unsigned long*>(bytes.c_str()
                        + section->getOriginalOffset());
                    auto size = section->getSize();
                    for(size_t i = 0; i*sizeof(unsigned long) < size; i += 2) {
                        if(p[i] == DT_NULL) {
                            break;
                        }
                        else if(p[i] == DT_INIT) {
                            firstInit = p[i+1];
                        }
                    }
                }
            }
        }
        if(firstInit) {
            content->addPointer([this, module, firstInit] () {
                Function *function = nullptr;
                if(module->getElfSpace()->getSymbolList()) {
                    auto symbol = module->getElfSpace()->getSymbolList()->find(firstInit);
                    function = ChunkFind2(getData()->getProgram())
                        .findFunctionInModule(symbol->getName(), module);
                }
                else {
                    std::string name2 = StreamAsString() << "fuzzyfunc-0x" << std::hex << firstInit;
                    function = ChunkFind2(getData()->getProgram())
                        .findFunctionInModule(name2.c_str(), module);
                    // if not found, may have a name like _init instead.
                    if(!function) {
                        function = ChunkFind2(getData()->getProgram())
                            .findFunctionInModule("_init", module);
                    }
                }
                LOG(1, "Found _init at " << function->getAddress());
                return function->getAddress();
            });
        }
    }

    for(auto link : initFunctions) {
        content->addPointer([link] () { return link->getTargetAddress(); });
    }

    initArraySection->setContent(content);
}

void MakeInitArray::makeInitArraySectionLinks() {
    auto initArraySection = getData()->getSection(".init_array");
    auto content = dynamic_cast<InitArraySectionContent *>(
        initArraySection->getContent());
    auto main = getData()->getProgram()->getMain();
    auto func = CIter::named(main->getFunctionList())->find("__libc_csu_init");
    if(!func) {
        auto entry = dynamic_cast<Function *>(getData()->getProgram()->getEntryPoint());
        if(entry) {
            auto block = entry->getChildren()->getIterable()->get(0);
            int counter = 0;
            for(auto instr : CIter::children(block)) {
                if(auto link = instr->getSemantic()->getLink()) {
                    ++counter;
                    if(counter == 2) {
                        func = dynamic_cast<Function *>(link->getTarget());
                        break;
                    }
                }
            }
        }
        if(!func) {
            LOG(1, "Warning: MakeInitArray can't find __libc_csu_init");
            return;
        }
    }
    auto block = func->getChildren()->getIterable()->get(0);
    int counter = 0;
    for(auto instr : CIter::children(block)) {
        if(auto link = instr->getSemantic()->getLink()) {
            ++counter;
            if(counter == 1) {
                // can't be deferred because otherwise code generation picks up old value
                //content->addCallback([initArraySection, instr, link]() {
                    auto addr = initArraySection->getHeader()->getAddress();
                    addr -= instr->getAddress() + instr->getSize();
                    instr->getSemantic()->setLink(new UnresolvedLink(addr));
                    dynamic_cast<LinkedInstruction *>(instr->getSemantic())
                        ->clearAssembly();
                    LOG(0, "Change link from 0x" << link->getTargetAddress()
                        << " to 0x" << addr << " for " << instr->getAddress());
                //});
            }
            if(counter == 2) {
                //content->addCallback([initArraySection, instr, link]() {
                    auto addr = initArraySection->getHeader()->getAddress()
                        + initArraySection->getContent()->getSize();
                    addr -= instr->getAddress() + instr->getSize();
                    instr->getSemantic()->setLink(new UnresolvedLink(addr));
                    dynamic_cast<LinkedInstruction *>(instr->getSemantic())
                        ->clearAssembly();
                    LOG(0, "Change link from 0x" << link->getTargetAddress()
                        << " to 0x" << addr << " for " << instr->getAddress());
                //});
            }

            if(counter >= 2) break;
        }
    }
}

void MakeGlobalPLT::execute() {
    collectPLTEntries();
    makePLTData();
    makePLTCode();
}

void MakeGlobalPLT::collectPLTEntries() {
    for(auto module : CIter::children(getData()->getProgram())) {
        for(auto plt : CIter::plts(module)) {
            if(plt->getTarget()) continue;

            auto extsym = plt->getExternalSymbol();
            if(!extsym) {
                LOG(0, "PLT entry has no external symbol!");
                continue;
            }

            LOG(9, "Found unresolved PLT entry [" << plt->getName() << "]");
            entries.push_back(plt);
        }
    }
    LOG(9, "In MakeGlobalPLT: found " << std::dec << entries.size()
        << " unresolved PLT entries.");
}

void MakeGlobalPLT::makePLTData() {
    {
        /*gotpltSection = new Section(".g.got.plt",
            SHT_PROGBITS, SHF_ALLOC | SHF_WRITE);*/
        gotpltSection = (*getData()->getSectionList())[".g.got.plt"];

        // 3 slots needed for GOT padding
        size_t contentLength = sizeof(address_t) * (entries.size()+3);
        char *content = new char[contentLength];
        std::memset(content, 0, contentLength);

        gotpltSection->setContent(new DeferredString(content, contentLength));
//        getData()->getSectionList()->addSection(gotpltSection);
    }

    // make .rela.plt section for function references
    {
        /*auto relaPltSection = new Section(".rela.plt",
            SHT_RELA, SHF_ALLOC | SHF_INFO_LINK);*/
        auto relaPltSection = (*getData()->getSectionList())[".rela.plt"];

        auto content = new DataRelocSectionContent(
            new SectionRef(getData()->getSectionList(), ".dynstr"),
                getData()->getSectionList());

        size_t index = 3; // start from index 3
        for(auto plt : entries) {
            content->addPLTRef(gotpltSection, plt, index);
            index ++;
        }

        relaPltSection->setContent(content);
        //getData()->getSectionList()->addSection(relaPltSection);
    }

    // MakePaddingSection(0x1000, true).execute();
}

void MakeGlobalPLT::makePLTCode() {
    {
        MakePaddingSection makePadding(0);
        makePadding.setData(getData());
        makePadding.setConfig(getConfig());
        makePadding.execute();
    }

    auto pltSection = new Section(".plt",
        SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR);
    auto content = new PLTCodeContent(gotpltSection, pltSection);
    pltSection->setContent(content);
    getData()->getSectionList()->addSection(pltSection);

    // add special entry 0 for name resolution
    content->addEntry(nullptr, 0);
    // add the rest of the PLT entries
    size_t index = 1;
    for(auto plt : entries) {
        content->addEntry(plt, index);
        index ++;
    }

    // MakePaddingSection(0x1000, false).execute();
}

void ElfFileWriter::execute() {
    updateOffsets();
    serialize();
}

void ElfFileWriter::updateOffsets() {
    // every Section is written to the file, even those without SectionHeaders
    size_t offset = 0;
    for(auto section : *getSectionList()) {
        LOG(1, "section [" << section->getName() << "] is at offset " << std::dec << offset);
        section->setOffset(offset);
        offset += section->getContent()->getSize();
    }
}

void ElfFileWriter::serialize() {
    std::ofstream fs(filename, std::ios::out | std::ios::binary);
    if(!fs.is_open()) {
        LOG(0, "Cannot open executable file [" << filename << "]");
        std::cerr << "Cannot open executable file [" << filename << "]" << std::endl;
        LOG(0, "");
        LOG(0, "*******************************************************");
        LOG(0, "**** PLEASE RE-RUN WITH DIFFERENT OUTPUT FILENAME! ****");
        return;
    }
    for(auto section : *getSectionList()) {
        LOG(1, "serializing " << section->getName()
            << " @ " << std::hex << section->getOffset()
            << " of size " << std::dec << section->getContent()->getSize());
        if(section->getOffset() != fs.tellp()) {
            LOG(1, " WARNING: section offset does not match file position");
        }
        fs << *section;
    }
    fs.close();
    chmod(filename.c_str(), 0744);
}

MakePaddingSection::MakePaddingSection(size_t desiredAlignment, bool isIsolatedPadding)
    : desiredAlignment(desiredAlignment), isIsolatedPadding(isIsolatedPadding) {

    setName(StreamAsString() << "MakePaddingSection{align=" << std::hex
        << desiredAlignment << ",isIsolated=" << (isIsolatedPadding ? '1':'0'));
}

void MakePaddingSection::execute() {
    // We could assign unique names to the padding sections, but since we
    // never look them up by name in SectionList, it doesn't actually matter.
    auto paddingSection = new Section(
        isIsolatedPadding ? "=padding" : "=intra-padding");
    auto paddingContent = new PagePaddingContent(
        getData()->getSectionList()->back(), desiredAlignment, isIsolatedPadding);
    paddingSection->setContent(paddingContent);
    getData()->getSectionList()->addSection(paddingSection);
}

