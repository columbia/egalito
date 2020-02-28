#include <set>
#include <fstream>
#include <string.h>
#include "anygen.h"
#include "modulegen.h"
#include "concretedeferred.h"
#include "transform/sandbox.h"
#include "chunk/concrete.h"
#include "instr/concrete.h"
#include "util/streamasstring.h"
#include "log/log.h"
#include "config.h"

AnyGen::AnyGen(Module *module, MemoryBufferBacking *backing)
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
    {
        ModuleGen::Config config;
        config.setCodeBacking(backing);
        ModuleGen moduleGen(config, module, &sectionList);
        moduleGen.makeText();
        moduleGen.makeDataSections();
    }
    makeShdrTable();  // don't create new shdrs after this
    makeSectionSymbols();
    updateOffsets();  // don't insert any new bytes after this
    serialize(filename);
}

void AnyGen::makeHeader() {
    // Generate an ELF header for the current platform.
    auto header = new ElfXX_Ehdr();
    auto deferred = new DeferredValueImpl<ElfXX_Ehdr>(header);

    // set up e_ident field
    memset(header->e_ident, 0, EI_NIDENT);
    memcpy(reinterpret_cast<char *>(header->e_ident), ELFMAG, SELFMAG);
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
        if(module == program->getMain() && program->getEntryPoint()) {
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

void AnyGen::makeSectionSymbols() {
    // update section indices in symbol table
    auto shdrTable = sectionList["=shdr_table"]->castAs<ShdrTableContent *>();
    auto symtab = sectionList[".symtab"]->castAs<SymbolTableContent *>();

    // add section symbols
    for(auto shdr : *shdrTable) {
        auto section = shdrTable->getKey(shdr);
        if(!section->getHeader()) continue;
        if(section->getHeader()->getShdrType() == SHT_NULL) continue;

        auto symbol = new Symbol(0, 0, "",
            Symbol::typeFromElfToInternal(STT_SECTION),
            Symbol::bindFromElfToInternal(STB_LOCAL),
            0, sectionList.indexOf(section));
        symtab->addSectionSymbol(symbol);
    }
    symtab->recalculateIndices();
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
    return sectionList.indexOf(section);
}

size_t AnyGen::shdrIndexOf(const std::string &name) {
    return sectionList.indexOf(name);
}
