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
#include "pass/chunkpass.h"
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

        // .dynsym
        auto dynsym = new SymbolTableContent(stringList);
        auto dynsymSection = new Section(".dynsym", SHT_DYNSYM);
        //auto dynsymSection = getSection(".dynsym");
        dynsymSection->setContent(dynsym);
        dynsym->addNullSymbol();
        // other symbols will be added later
        getSectionList()->addSection(dynsymSection);

        // .gnu.hash
        auto gnuhash = new GnuHashSectionContent();
        auto gnuhashSection = new Section(".gnu.hash", SHT_GNU_HASH, SHF_ALLOC);
        gnuhashSection->setContent(gnuhash);
        getSectionList()->addSection(gnuhashSection);

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
    if(!getConfig()->isPositionIndependent()) {
        header->e_type = ET_EXEC;
    }
    else {
        header->e_type = ET_DYN;
    }
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

        auto symtabSection = getSection(".symtab");
        symtabSection->getHeader()->setSectionLink(
            new SectionRef(getSectionList(), ".strtab"));
    }
    if(getConfig()->isDynamicallyLinked()) {
        auto dynsymSection = getSection(".dynsym");

        dynsymSection->getHeader()->setSectionLink(
            new SectionRef(getSectionList(), ".dynstr"));
        dynsymSection->getHeader()->setShdrFlags(SHF_ALLOC);
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
            else if(auto v = dynamic_cast<GnuHashSectionContent *>(section->getContent())) {
                deferred->addFunction([this, sectionList, v] (ElfXX_Shdr *shdr) {
                    shdr->sh_addralign = 8;
                    shdr->sh_entsize = 0;
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

    {
        auto dynsym = getSection(".dynsym")->castAs<SymbolTableContent *>();
        dynsym->recalculateIndices();
    }
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

static const char *getSoname(ElfMap *elf) {
    auto dynamic = elf->getSectionReadPtr<unsigned long *>(".dynamic");
    if(!dynamic) return nullptr;  // statically linked
    auto strtab = elf->getDynstrtab();

    for(unsigned long *pointer = dynamic; *pointer != DT_NULL; pointer += 2) {
        unsigned long type = pointer[0];
        unsigned long value = pointer[1];

        if(type == DT_SONAME) {
            auto name = strtab + value;
            return name;
        }
    }
    return nullptr;
}

void BasicElfStructure::makeDynamicSection() {
    auto dynamicSection = getSection(".dynamic");
    auto dynamic = dynamicSection->castAs<DynamicSectionContent *>();

    auto dynstr = getSection(".dynstr")->castAs<DeferredStringList *>();
    if(addLibDependencies) {
        for(auto lib : CIter::children(getData()->getProgram()->getLibraryList())) {
            if(lib->getModule()) continue;
            dynamic->addPair(DT_NEEDED, dynstr->add(lib->getName(), true));
        }

#if 1
        auto first = getData()->getProgram()->getFirst();
        if(first->getLibrary()->getRole() == Library::ROLE_LIBC) {
            dynamic->addPair(DT_NEEDED,
                dynstr->add("ld-linux-x86-64.so.2", true));
        }

        if(first->getLibrary()->getRole() != Library::ROLE_MAIN) {
            auto soName = getSoname(first->getElfSpace()->getElfMap());
            if(soName) {
                dynamic->addPair(DT_SONAME, dynstr->add(soName, true));
            }
        }
#endif
    }
    else {
        // Add DT_NEEDED dependency on ld.so because we combine libc into
        // our executable, and libc uses _rtld_global{,_ro} from ld.so.
        dynamic->addPair(DT_NEEDED,
            dynstr->add("ld-linux-x86-64.so.2", true));
    }

    dynamic->addPair(DT_STRTAB, [this] () {
        auto dynstrSection = getSection(".dynstr");
        return dynstrSection->getHeader()->getAddress();
    });

    dynamic->addPair(DT_SYMTAB, [this] () {
        auto dynsymSection = getSection(".dynsym");
        return dynsymSection->getHeader()->getAddress();
    });

    dynamic->addPair(DT_GNU_HASH, [this] () {
        auto gnuhashSection = getSection(".gnu.hash");
        return gnuhashSection->getHeader()->getAddress();
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

    if(addLibDependencies) {
        auto first = getData()->getProgram()->getFirst();
        if(first->getLibrary()->getRole() == Library::ROLE_LIBC) {
            dynamic->addPair(DT_FLAGS, DF_STATIC_TLS | DF_BIND_NOW);
        }
        /*else if(first->getLibrary()->getRole() == Library::ROLE_MAIN) {
            dynamic->addPair(DT_FLAGS, DF_PIE);
        }*/
        else {
            dynamic->addPair(DT_FLAGS, DF_BIND_NOW);
        }
    }
    else {
        dynamic->addPair(DT_FLAGS, DF_STATIC_TLS | DF_BIND_NOW);
    }

    // PLT-related entries
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

    // terminating pair
    dynamic->addPair(0, 0);

    dynamicSection->setContent(dynamic);
    dynamicSection->getHeader()->setSectionLink(new SectionRef(getSectionList(), ".dynstr"));
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
        dynSegment->addContains(getSection(".gnu.hash"));
        dynSegment->addContains(getSection(".rela.dyn"));
        dynSegment->addContains(getSection(".dynamic"));
        phdrTable->add(dynSegment, 0x400000);

        auto dynSegment2 = new SegmentInfo(PT_LOAD, PF_R | PF_W, /*0x400000*/ 0x1000);
        dynSegment2->addContains(getSection(".g.got.plt"));
        dynSegment2->addContains(getSection(".rela.plt"));
        phdrTable->add(dynSegment2, 0x500000);

        auto pltSegment = new SegmentInfo(PT_LOAD, PF_R | PF_X, 0x1000);
        pltSegment->addContains(getSection(".plt"));
        // XXX: currently 0x600000 is hardcoded in UpdatePLTLinks()
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

void MakeInitArray::addInitFunction(InitArraySectionContent *content,
    std::function<address_t ()> value) {

    if(getConfig()->isPositionIndependent()) {
        auto relaDyn = getData()->getSection(".rela.dyn")->castAs<DataRelocSectionContent *>();

        // !!! Hardcoding this address for now. After =elfheader & .interp
        const address_t INIT_ARRAY_ADDR = 0x20005c;
        auto offset = content->getSize();
        relaDyn->addDataAddressRef(INIT_ARRAY_ADDR + offset, value);
        content->addPointer([] () { return address_t(0); });
    }
    else {
        content->addPointer(value);
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
            addInitFunction(content, [this, module, firstInit] () {
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
                LOG(1, "Found _init at " << std::hex << function->getAddress());
                return function->getAddress();
            });
        }
    }

    for(auto link : initFunctions) {
        addInitFunction(content, [link] () { return link->getTargetAddress(); });
    }

    initArraySection->setContent(content);
}

Function *MakeInitArray::findLibcCsuInit(Chunk *entryPoint) {
    auto entry = dynamic_cast<Function *>(entryPoint);
    if(!entry) return nullptr;

    if(entry->getChildren()->genericGetSize() == 0) return nullptr;
    auto block = entry->getChildren()->getIterable()->get(0);

    for(auto instr : CIter::children(block)) {
        if(auto link = instr->getSemantic()->getLink()) {
#ifdef ARCH_X86_64
            if(!instr->getSemantic()->getAssembly()) continue;
            auto ops = instr->getSemantic()->getAssembly()->getAsmOperands();
            if(ops->getOpCount() > 1) { 
                auto op1 = ops->getOperands()[1];
                if(op1.type == X86_OP_REG && op1.reg == X86_REG_RCX) {
                    return dynamic_cast<Function *>(link->getTarget());
                }
            }
#else
#error "Need __libc_csu_init detection code for current platform!"
#endif
        }
    }
    return nullptr;
}

void MakeInitArray::makeInitArraySectionLinks() {
    auto initArraySection = getData()->getSection(".init_array");
    auto content = dynamic_cast<InitArraySectionContent *>(
        initArraySection->getContent());
    auto main = getData()->getProgram()->getMain();
    if(!main) return;
    auto func = CIter::named(main->getFunctionList())->find("__libc_csu_init");
    // if we didn't find __libc_csu_init directly, look for it by the link
    // present in _start during the call to __libc_start_main
    if(!func) {
        auto entry = getData()->getProgram()->getEntryPoint();
        func = findLibcCsuInit(entry);
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
    auto &entryMap = getData()->getPLTIndexMap()->getEntryMap();

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
            entryMap[plt] = entries.size();
        }
    }
    LOG(9, "In MakeGlobalPLT: found " << std::dec << entries.size()
        << " unresolved PLT entries.");
}

void MakeGlobalPLT::makePLTData() {
    {
        gotpltSection = (*getData()->getSectionList())[".g.got.plt"];

        // 3 slots needed for GOT padding
        size_t contentLength = sizeof(address_t) * (entries.size()+3);
        char *content = new char[contentLength];
        std::memset(content, 0, contentLength);

        gotpltSection->setContent(new DeferredString(content, contentLength));
    }

    // make .rela.plt section for function references
    {
        auto relaPltSection = (*getData()->getSectionList())[".rela.plt"];

        auto content = new DataRelocSectionContent(
            new SectionRef(getData()->getSectionList(), ".dynstr"),
                getData()->getSectionList());

        size_t index = 3; // start from index 3
        for(auto plt : entries) {
            if(!plt->isPltGot()) {
                content->addPLTRef(gotpltSection, plt, index);
            }
            index ++;
        }

        relaPltSection->setContent(content);
    }

    // add gotplt relocations to rela.dyn
    {
        auto relaDynSection = (*getData()->getSectionList())[".rela.dyn"];
        auto dynContent = relaDynSection->castAs<DataRelocSectionContent *>();

        size_t index = 3; // start from index 3
        for(auto plt : entries) {
            if(plt->isPltGot()) {
                dynContent->addPLTRef(gotpltSection, plt, index);
            }
            index ++;
        }
    }
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

    getData()->getPLTIndexMap()->setPltSection(pltSection);
}

void UpdatePLTLinks::execute() {
    // now we want to do a pass across everything
    // and look for PLTTrampoline links.
    LOG(9, "Updating PLT references...");

    auto &entryMap = getData()->getPLTIndexMap()->getEntryMap();

    class Updater : public ChunkPass {
    private:
        std::map<PLTTrampoline *, size_t> &entryMap;
        address_t pltBase;
    public:
        Updater(std::map<PLTTrampoline *, size_t> &entryMap, address_t pltBase)
            : entryMap(entryMap), pltBase(pltBase) {}

        virtual void visit(Instruction *instruction) {
            auto cfi =
                dynamic_cast<ControlFlowInstruction *>(instruction->getSemantic());
            if(!cfi) return;

            auto link = cfi->getLink();
            auto pltLink = dynamic_cast<PLTLink *>(link);
            if(!pltLink) return;
            auto target = pltLink->getPLTTrampoline();
            size_t index = entryMap[target];
            LOG(9, "    redirecting 0x" << std::hex << instruction->getAddress()
                << " to index " << std::dec << index);

            // this means we don't have a PLT entry for it.
            if(index == 0) {
                return;
            }

            // set the link to target the absolute address of the PLT.
            address_t address = pltBase + (index * 0x10);
            cfi->setLink(new UnresolvedRelativeLink(address));
        }
    };

    // XXX: this really shouldn't be hardcoded!
    Updater updater(entryMap, 0x600000);
    getData()->getProgram()->accept(&updater);
}

void CopyDynsym::execute() {
    auto dynsym = getData()->getSection(".dynsym")->castAs<SymbolTableContent *>();
    for(auto module : CIter::children(getData()->getProgram())) {
        for(auto func : CIter::children(module->getFunctionList())) {
            auto dsym = func->getDynamicSymbol();
            if(!dsym) continue;

            auto value = dynsym->addSymbol(func, dsym);
            value->addFunction([this] (ElfXX_Sym *symbol) {
                symbol->st_shndx = getData()->getSectionList()->indexOf(".text");
            });
        }
    }
}

// hash function stolen from binutils/bfd/elf.c:221
static unsigned long
bfd_elf_gnu_hash (const char *namearg)
{
  const unsigned char *name = (const unsigned char *) namearg;
  unsigned long h = 5381;
  unsigned char ch;

  while ((ch = *name++) != '\0')
    h = (h << 5) + h + ch;
  return h & 0xffffffff;
}

void MakeDynsymHash::execute() {
    auto gnuhash = getData()->getSection(".gnu.hash")->castAs<GnuHashSectionContent *>();
    auto dynsym = getData()->getSection(".dynsym")->castAs<SymbolTableContent *>();
    dynsym->recalculateIndices();

    auto dynstr = getData()->getSection(".dynstr")->castAs<DeferredStringList *>();
    std::ostringstream dynstrStream;
    dynstr->writeTo(dynstrStream);
    auto dynstrData = dynstrStream.str();

    bucketList.resize(1011);
    //bucketList.resize(10007);

    bool hashing = false;
    size_t firstHashedSymbol = 0;
    for(auto sym : *dynsym) {
        auto elfSym = sym->getElfPtr();
        LOG(1, "elfSym address " << elfSym->st_value);
        // Skip the undefined symbols (first, address == 0), don't hash them.
        // These will be looked up in another library, not in our own .dynsym.
        if(elfSym->st_value) hashing = true;
        if(!hashing) {
            firstHashedSymbol ++;
            continue;
        }

        auto name = dynstrData.c_str() + elfSym->st_name;
        auto hash = bfd_elf_gnu_hash(name);

        LOG(1, "elfSym name [" << name << "] hash 0x" << std::hex << hash);
        bucketList[hash % bucketList.size()].push_back(name);
    }

    size_t index = 0;
    for(const auto &bucket : bucketList) {
        for(const auto &name : bucket) {
            indexMap[name] = index++;
        }
    }

    typedef uint64_t BloomType;  // Assumes ELFCLASS64
    const uint32_t bloomShift = 5;
    std::vector<BloomType> bloomList; //= {-1ul, -1ul};
    for(size_t i = 0; i < 0x100; i ++) bloomList.push_back(-1ul);

    gnuhash->add(static_cast<uint32_t>(bucketList.size()));     // nbuckets
    gnuhash->add(static_cast<uint32_t>(firstHashedSymbol));     // symoffset
    gnuhash->add(static_cast<uint32_t>(bloomList.size()));      // bloom_size
    gnuhash->add(static_cast<uint32_t>(bloomShift));            // bloom_shift

    // bloom_list
    for(auto bloom : bloomList) {
        gnuhash->add(bloom);
    }

    // bucket_list
    size_t symIndex = firstHashedSymbol;
    for(const auto &bucket : bucketList) {
        if(bucket.size()) {
            gnuhash->add(static_cast<uint32_t>(symIndex));
            symIndex += bucket.size();
        }
        else {
            // 0's observed in real binaries
            gnuhash->add(static_cast<uint32_t>(0));
        }
    }

    // chain
    for(const auto &bucket : bucketList) {
        for(const auto &name : bucket) {
            auto hash = bfd_elf_gnu_hash(name.c_str());
            //uint32_t value = (hash % bucketList.size()) & ~1;
            uint32_t value = hash & ~1;
            if(name == bucket.back()) value += 1;
            gnuhash->add(value);
        }
    }
    
    // .dymsym sorting
    auto oldValueMap = dynsym->getValueMap();  // deep copy
    dynsym->clearAll();
    for(const auto &pair : oldValueMap) {
        auto key = pair.first;
        auto val = pair.second;
        auto it = indexMap.find(key.getName());
        if(it != indexMap.end()) {
            LOG(1, "Found symbol index for name [" << (*it).first << "] at index "
                << (*it).second);
            key.setTableIndex((*it).second);
        }
        dynsym->insertSorted(key, val);
    }

    dynsym->recalculateIndices();

    //auto newValueMap = dynsym->getValueMap();  // deep copy
    //for(const auto &val : *dynsym) {
    //    LOG(1, "new order for symbol with name [" << val->getName() << "]");
    //}
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

