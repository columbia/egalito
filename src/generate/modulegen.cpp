#include <set>
#include <fstream>
#include <string.h>
#include "modulegen.h"
#include "concretedeferred.h"
#include "transform/sandbox.h"
#include "chunk/concrete.h"
#include "instr/concrete.h"
#include "util/streamasstring.h"
#include "log/log.h"
#include "config.h"

ModuleGen::ModuleGen(Config config, Module *module, SectionList *sectionList)
    : config(config), module(module), sectionList(sectionList) {

}

void ModuleGen::makeDataSections() {
    // Before all LOAD segments, we need to put padding.
    makePaddingSection(0);

    auto phdrTable = getSection("=phdr_table")->castAs<PhdrTableContent *>();
    auto regionList = module->getDataRegionList();
    for(auto region : CIter::children(regionList)) {
        auto loadSegment = new SegmentInfo(PT_LOAD, PF_R | PF_W, 0x200000);

        for(auto section : CIter::children(region)) {
            switch(section->getType()) {
            case DataSection::TYPE_DATA: {
                LOG(0, "DATA section " << section->getName());
                makePaddingSection(section->getAddress() & (0x200000-1));

                // by default, make everything writable
                auto dataSection = new Section(section->getName(),
                    SHT_PROGBITS, SHF_ALLOC | SHF_WRITE);
                auto content = new DeferredString(region->getDataBytes()
                    .substr(section->getOriginalOffset(), section->getSize()));
                dataSection->setContent(content);
                dataSection->getHeader()->setAddress(section->getAddress());
                sectionList->addSection(dataSection);
                loadSegment->addContains(dataSection);
                break;
            }
            case DataSection::TYPE_BSS: {
                LOG(0, "BSS section " << section->getName());
                makePaddingSection(section->getAddress() & (0x200000-1));

                auto bssSection = new Section(section->getName(),
                    SHT_NOBITS, SHF_ALLOC | SHF_WRITE);
                bssSection->setContent(new DeferredString(""));
                bssSection->getHeader()->setAddress(section->getAddress());
                sectionList->addSection(bssSection);
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

void ModuleGen::makeText() {
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
    auto phdrTable = getSection("=phdr_table")->castAs<PhdrTableContent *>();
    for(auto range : codeRegions) {
        auto address = range.getStart();
        auto size = range.getSize();
        LOG(1, "map " << std::hex << address << " size " << size);

        std::string name;
        if(codeRegions.size() == 1 && !config.getUniqueSectionNames()) {
            name = ".text";
        } 
        else {
            name = StreamAsString() << ".text.0x" << std::hex << address;
        }
        
        auto textSection = new Section(name.c_str(), SHT_PROGBITS,
            SHF_ALLOC | SHF_EXECINSTR);
        DeferredString *textValue = nullptr;
        if(auto backing = config.getCodeBacking()) {
            // Don't modify backing after this point to avoid invalidating c_str
            auto copy = new std::string(backing->getBuffer());
            textValue = new DeferredString(
                reinterpret_cast<const char *>(copy->c_str()),
                size);
        }
        else {
            textValue = new DeferredString(
                reinterpret_cast<const char *>(address), size);
        } 
        if(config.isKernel()) {
            textSection->getHeader()->setAddress(LINUX_KERNEL_CODE_BASE);
        }
        else {
            textSection->getHeader()->setAddress(address);
        }
        textSection->setContent(textValue);

        sectionList->addSection(textSection);

        makeRelocSectionFor(name);
        makeSymbolsAndRelocs(address, size, name);

        auto loadSegment = new SegmentInfo(PT_LOAD, PF_R | PF_X, 0x1000);
        loadSegment->addContains(textSection);
        phdrTable->add(loadSegment);
    }
}

void ModuleGen::makeTextAccumulative() {
    auto backing = config.getCodeBacking();
    auto address = backing->getBase();
    auto size = backing->getSize();
    makeRelocSectionFor(".text");
    makeSymbolsAndRelocs(address, size, ".text");
}

void ModuleGen::makeRelocSectionFor(const std::string &otherName) {
#if 0
    auto reloc = new RelocSectionContent2(&sectionList,
        new SectionRef(&sectionList, otherName));
    auto relocSection = new Section(".rela" + otherName, SHT_RELA, SHF_INFO_LINK);
    relocSection->setContent(reloc);

    sectionList->addSection(relocSection);
#endif
}

void ModuleGen::makeSymbolsAndRelocs(address_t begin, size_t size,
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

        if(config.isKernel()) {
            // fix addresses for kernel generation
            auto backing = config.getCodeBacking();
            func->getPosition()->set(func->getAddress() - backing->getBase()
                + LINUX_KERNEL_CODE_BASE);
        }

        LOG(1, "making symbol for " << func->getName());
        makeSymbolInText(func, textSection);
#if 0
        makeRelocInText(func, textSection);
#endif
        
        if(config.isKernel()) { 
            // undo address fix
            auto backing = config.getCodeBacking();
            func->getPosition()->set(backing->getBase() + func->getAddress());
        }
    }

#if 0
    // Handle any other types of symbols that need generating.
    for(auto sym : *elfSpace->getSymbolList()) {
        if(sym->isFunction()) continue;  // already handled
        if(blacklistedSymbol(sym->getName())) continue;  // blacklisted

        // undefined symbol
        if(sym->getSectionIndex() == SHN_UNDEF) {
            auto symtab = getSection(".symtab")->castAs<SymbolTableContent *>();
            symtab->addUndefinedSymbol(sym);
        }
    }
#endif
}

void ModuleGen::makeSymbolInText(Function *func, const std::string &textSection) {
    auto symtab = getSection(".symtab")->castAs<SymbolTableContent *>();

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

void ModuleGen::makeRelocInText(Function *func, const std::string &textSection) {
    auto reloc = getSection(".rela" + textSection)->castAs<RelocSectionContent2 *>();

    for(auto block : CIter::children(func)) {
        for(auto instr : CIter::children(block)) {
            if(auto link = instr->getSemantic()->getLink()) {
                //LOG(1, "adding relocation at " << instr->getName());

                if(link->getTarget()) {
                    Chunk *functionTarget = link->getTarget();
                    while(functionTarget && !dynamic_cast<Function *>(functionTarget)) {
                        functionTarget = functionTarget->getParent();
                    }

                    if(functionTarget) {
                        auto func = static_cast<Function *>(functionTarget);
                        auto symtab = getSection(".symtab")
                            ->castAs<SymbolTableContent *>();
                        auto sym = symtab->find(SymbolInTable(
                            SymbolTableContent::getTypeFor(func),
                            func->getSymbol()));
                        if(sym) {
                            //reloc->addFunctionRef();
                            //continue;
                        }
                    }
                }

                auto target = link->getTargetAddress();
                DataSection *targetSection = module->getDataRegionList()
                    ->findDataSectionContaining(target);

                if(targetSection) {
                    reloc->addDataRef(instr->getAddress(), target, targetSection);
                }
            }
        }
    }
}

void ModuleGen::makePaddingSection(size_t desiredAlignment) {
    // We could assign unique names to the padding sections, but since we
    // never look them up by name in SectionList, it doesn't actually matter.
    auto paddingSection = new Section("=padding");
    auto paddingContent = new PagePaddingContent(
        sectionList->back(), desiredAlignment);
    paddingSection->setContent(paddingContent);
    sectionList->addSection(paddingSection);
}

size_t ModuleGen::shdrIndexOf(Section *section) {
#if 0
    auto shdrTableSection = getSection("=shdr_table");
    auto shdrTable = shdrTableSection->castAs<ShdrTableContent *>();
    return shdrTable->indexOf(shdrTable->find(section));
#else
    return sectionList->indexOf(section);
#endif
}

size_t ModuleGen::shdrIndexOf(const std::string &name) {
#if 0
    auto shdrTableSection = getSection("=shdr_table");
    auto shdrTable = shdrTableSection->castAs<ShdrTableContent *>();
    return shdrTable->indexOf(shdrTable->find(sectionList[name]));
#else
    return sectionList->indexOf(name);
#endif
}

bool ModuleGen::blacklistedSymbol(const std::string &name) {
    return false;
}
