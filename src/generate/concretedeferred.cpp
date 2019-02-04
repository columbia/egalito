#include <cstring>  // for memset
#include "concretedeferred.h"
#include "section.h"
#include "sectionlist.h"
#include "elf/elfspace.h"
#include "elf/symbol.h"
#include "chunk/function.h"
#include "chunk/dataregion.h"
#include "chunk/link.h"
#include "instr/instr.h"
#include "instr/concrete.h"
#include "log/log.h"
#include "config.h"

bool SymbolInTable::operator < (const SymbolInTable &other) const {
    if(tableIndex < other.tableIndex) return true;
    if(tableIndex > other.tableIndex) return false;

    if(type < other.type) return true;
    if(type > other.type) return false;

#if 1
    // NULL symbols are ordered first
    bool null1 = (sym == nullptr);
    bool null2 = (other.get() == nullptr);
    if(null1 && !null2) return true;
    if(!null1 && null2) return false;
    if(null1 && null2) return false;  // shouldn't happen
#endif

#if 0
    auto address1 = sym->getAddress();
    auto address2 = other.get()->getAddress();
    if(!address1 && address2) return true;
    if(address1 && !address2) return false;
    if(address1 && address2) {
        if(address1 < address2) return true;
        if(address1 > address2) return false;
    }
#endif

    int nameCompare = std::strcmp(sym->getName(), other.get()->getName());
    if(nameCompare < 0) return true;
    if(nameCompare > 0) return false;

    int section1 = sym->getSectionIndex();
    int section2 = other.get()->getSectionIndex();

    return section1 < section2;
}

bool SymbolInTable::operator == (const SymbolInTable &other) const {
#if 1
    // right now we never copy Symbols, so we can just compare addresses
    return sym == other.get();
#else
    if(sym == other.get()) return true;
    return type == other.type
        && ((sym == nullptr) == (other.get() == nullptr))
        && std::strcmp(sym->getName(), other.get()->getName()) == 0
        && sym->getSectionIndex() == other.get()->getSectionIndex()
        && tableIndex == other.tableIndex;
#endif
}

std::string SymbolInTable::getName() const {
    return sym ? sym->getName() : "(null)";
}

void SymbolTableContent::addNullSymbol() {
    auto symbol = new ElfXX_Sym();
    symbol->st_name = strtab->add("", 1);  // add empty name
    symbol->st_info = 0;
    symbol->st_other = STV_DEFAULT;
    symbol->st_shndx = 0;
    symbol->st_value = 0;
    symbol->st_size = 0;
    auto sit = SymbolInTable(SymbolInTable::TYPE_NULL);
    insertSorted(sit, new DeferredType(symbol));
    firstGlobalIndex ++;
}

void SymbolTableContent::addSectionSymbol(Symbol *sym) {
    ElfXX_Sym *symbol = new ElfXX_Sym();
    symbol->st_name = 0;
    symbol->st_info = ELFXX_ST_INFO(
        Symbol::bindFromInternalToElf(sym->getBind()),
        Symbol::typeFromInternalToElf(sym->getType()));
    symbol->st_other = STV_DEFAULT;
    symbol->st_shndx = sym->getSectionIndex();
    symbol->st_value = 0;
    symbol->st_size = 0;

    LOG(1, "added section symbol for " << symbol->st_shndx);

    auto value = new DeferredType(symbol);
    auto sit = SymbolInTable(SymbolInTable::TYPE_SECTION, sym);
    insertSorted(sit, value);
    firstGlobalIndex ++;

    auto i = sym->getSectionIndex();
    if(i >= sectionSymbols.size()) sectionSymbols.resize(i + 1);
    sectionSymbols[i] = value;
}

SymbolTableContent::DeferredType *SymbolTableContent
    ::addSymbol(Function *func, Symbol *sym) {

    if(!sym) {
        char *name = new char[func->getName().length() + 1];
        std::strcpy(name, func->getName().c_str());
        sym = new Symbol(0, 0, name,
            Symbol::TYPE_FUNC, Symbol::BIND_GLOBAL, 0, SHN_UNDEF);
    }

    if(sym->getBind() == Symbol::BIND_LOCAL) {
        auto sit = SymbolInTable(SymbolInTable::TYPE_LOCAL, sym);
        if(contains(sit)) return find(sit);
    }
    else {
        auto sit = SymbolInTable(func
            ? SymbolInTable::TYPE_GLOBAL
            : SymbolInTable::TYPE_UNDEF, sym);
        if(contains(sit)) return find(sit);
    }

    auto name = std::string(sym->getName());
    auto index = strtab->add(name, true);  // add name to string table

    ElfXX_Sym *symbol = new ElfXX_Sym();
    symbol->st_name = static_cast<ElfXX_Word>(index);
    symbol->st_info = ELFXX_ST_INFO(
        Symbol::bindFromInternalToElf(sym->getBind()),
        Symbol::typeFromInternalToElf(sym->getType()));
    symbol->st_other = STV_DEFAULT;
    symbol->st_shndx = SHN_UNDEF;
    symbol->st_value = func ? func->getAddress() : 0;
    symbol->st_size = func ? func->getSize() : 0;
    auto value = new DeferredType(symbol);
    if(sym->getBind() == Symbol::BIND_LOCAL) {
        auto sit = SymbolInTable(SymbolInTable::TYPE_LOCAL, sym);
        insertSorted(sit, value);
        firstGlobalIndex ++;
    }
    else {
        auto sit = SymbolInTable(func
            ? SymbolInTable::TYPE_GLOBAL
            : SymbolInTable::TYPE_UNDEF, sym);
        insertSorted(sit, value);
    }
    return value;
}

SymbolTableContent::DeferredType *SymbolTableContent
    ::addDataVarSymbol(DataVariable *var, Symbol *sym, address_t address, 
    size_t section) {

    // NOTE: caller may want to override the st_shndx in the symbol in a
    // deferred callback

    assert(sym);

    if(sym->getBind() == Symbol::BIND_LOCAL) {
        auto sit = SymbolInTable(SymbolInTable::TYPE_LOCAL, sym);
        if(contains(sit)) return find(sit);
    }
    else {
        auto sit = SymbolInTable(SymbolInTable::TYPE_GLOBAL, sym);
        if(contains(sit)) return find(sit);
    }

    auto name = std::string(sym->getName());
    auto index = strtab->add(name, true);  // add name to string table

    ElfXX_Sym *symbol = new ElfXX_Sym();
    symbol->st_name = static_cast<ElfXX_Word>(index);
    symbol->st_info = ELFXX_ST_INFO(
        Symbol::bindFromInternalToElf(sym->getBind()),
        Symbol::typeFromInternalToElf(sym->getType()));
    symbol->st_other = STV_DEFAULT;
    symbol->st_shndx = section;
    symbol->st_value = address;
    symbol->st_size = var ? var->getSize() : 0;
    auto value = new DeferredType(symbol);
    if(sym->getBind() == Symbol::BIND_LOCAL) {
        auto sit = SymbolInTable(SymbolInTable::TYPE_LOCAL, sym);
        insertSorted(sit, value);
        firstGlobalIndex ++;
    }
    else {
        auto sit = SymbolInTable(SymbolInTable::TYPE_GLOBAL, sym);
        insertSorted(sit, value);
    }
    return value;
}

SymbolTableContent::DeferredType *SymbolTableContent
    ::addPLTSymbol(PLTTrampoline *plt, Symbol *sym) {

    auto name = std::string(sym->getName());
    auto index = strtab->add(name, true);  // add name to string table

    ElfXX_Sym *symbol = new ElfXX_Sym();
    symbol->st_name = static_cast<ElfXX_Word>(index);
    symbol->st_info = ELFXX_ST_INFO(
        Symbol::bindFromInternalToElf(sym->getBind()),
        Symbol::typeFromInternalToElf(sym->getType()));
    symbol->st_other = STV_DEFAULT;
    symbol->st_shndx = SHN_UNDEF;
    symbol->st_value = plt ? plt->getAddress() : 0;
    symbol->st_size = plt ? plt->getSize() : 0;
    auto value = new DeferredType(symbol);
    auto sit = SymbolInTable(SymbolInTable::TYPE_PLT, sym);
    insertSorted(sit, value);
    firstGlobalIndex ++;
    return value;
}

SymbolTableContent::DeferredType *SymbolTableContent
    ::addUndefinedSymbol(Symbol *sym) {

    // uses st_shndx = SHN_UNDEF by default
    return addSymbol(nullptr, sym);
}

size_t SymbolTableContent::indexOfSectionSymbol(const std::string &section,
    SectionList *sectionList) {

    size_t index = sectionList->indexOf(section);
    return this->indexOf(sectionSymbols[index]);
}

SymbolInTable::type_t SymbolTableContent::getTypeFor(Function *func) {
    // !!! Function should know whether it is local or not...
    return (func->getSymbol()->getBind() == Symbol::BIND_LOCAL)
        ? SymbolInTable::TYPE_LOCAL : SymbolInTable::TYPE_GLOBAL;
}

ShdrTableContent::DeferredType *ShdrTableContent::add(Section *section) {
    auto shdr = new ElfXX_Shdr();
    std::memset(shdr, 0, sizeof(*shdr));

    auto deferred = new DeferredType(shdr);

    deferred->addFunction([this, section] (ElfXX_Shdr *shdr) {
        LOG(1, "generating shdr for section [" << section->getName() << "]");
        auto header = section->getHeader();
        //shdr->sh_name       = 0;
        shdr->sh_type       = header->getShdrType();
        shdr->sh_flags      = header->getShdrFlags();
        shdr->sh_addr       = header->getAddress();
        shdr->sh_offset     = section->getOffset();
        shdr->sh_size       = section->getContent() ?
            section->getContent()->getSize() : 0;
        shdr->sh_link       = header->getSectionLink()
            ? header->getSectionLink()->getIndex() : 0;
        shdr->sh_info       = 0;  // updated later for strtabs
        shdr->sh_addralign  = 1;
        shdr->sh_entsize    = 0;
    });

    DeferredMap<Section *, ElfXX_Shdr>::add(section, deferred);
    return deferred;
}

PhdrTableContent::DeferredType *PhdrTableContent::add(SegmentInfo *segment) {
    auto phdr = new ElfXX_Phdr();
    std::memset(phdr, 0, sizeof(*phdr));

    auto deferred = new DeferredType(phdr);

    deferred->addFunction([segment] (ElfXX_Phdr *phdr) {
        LOG(1, "generating phdr for segment of type " << segment->getType()
            << ", containing:");

        size_t fileSize = 0;
        for(auto section : segment->getContainsList()) {
            LOG(2, "    " << section->getName());
            fileSize += section->getContent()->getSize();
        }

        size_t offset = 0;
        address_t address = 0;
        if(!segment->getContainsList().empty()) {
            auto firstSection = segment->getContainsList()[0];
            offset = firstSection->getOffset();
            if(firstSection->getHeader()) {
                address = firstSection->getHeader()->getAddress();
            }
        }

        phdr->p_type    = segment->getType();
        phdr->p_flags   = segment->getFlags();
        phdr->p_offset  = offset;
        phdr->p_vaddr   = address;
        phdr->p_paddr   = address;
        phdr->p_filesz  = fileSize;
        phdr->p_memsz   = fileSize + segment->getAdditionalMemSize();
        phdr->p_align   = segment->getAlignment();

        if((phdr->p_vaddr & LINUX_KERNEL_BASE) == LINUX_KERNEL_BASE) {
            phdr->p_paddr -= LINUX_KERNEL_BASE;
        }
    });

    DeferredMap<SegmentInfo *, ElfXX_Phdr>::add(segment, deferred);
    return deferred;
}

PhdrTableContent::DeferredType *PhdrTableContent::add(SegmentInfo *segment,
    address_t address) {

    auto phdr = new ElfXX_Phdr();
    std::memset(phdr, 0, sizeof(*phdr));

    auto deferred = new DeferredType(phdr);

    deferred->addFunction([segment, address] (ElfXX_Phdr *phdr) {
        LOG(1, "generating phdr for segment of type " << segment->getType()
            << ", containing:");

        size_t fileSize = 0;
        for(auto section : segment->getContainsList()) {
            LOG(2, "    " << section->getName());
            fileSize += section->getContent()->getSize();
        }

        size_t offset = 0;
        if(!segment->getContainsList().empty()) {
            auto firstSection = segment->getContainsList()[0];
            offset = firstSection->getOffset();
        }

        address_t sectionAddress = address;
        for(auto sec : segment->getContainsList()) {
            if(sec->hasHeader()) {
                sec->getHeader()->setAddress(sectionAddress);
            }
            sectionAddress += sec->getContent()->getSize();
        }

        phdr->p_type    = segment->getType();
        phdr->p_flags   = segment->getFlags();
        phdr->p_offset  = offset;
        phdr->p_vaddr   = address;
        phdr->p_paddr   = address;
        phdr->p_filesz  = fileSize;
        phdr->p_memsz   = fileSize + segment->getAdditionalMemSize();
        phdr->p_align   = segment->getAlignment();

        if((phdr->p_vaddr & LINUX_KERNEL_BASE) == LINUX_KERNEL_BASE) {
            phdr->p_paddr -= LINUX_KERNEL_BASE;
        }
    });

    DeferredMap<SegmentInfo *, ElfXX_Phdr>::add(segment, deferred);
    return deferred;
}

void PhdrTableContent::assignAddressesToSections(SegmentInfo *segment, address_t addr) {
    /*if(segment->getContainsList().empty()) return;
    auto firstSection = segment->getContainsList()[0];

    if(!firstSection->hasHeader()) return;
    auto header = firstSection->getHeader();

    if(!header->getAddress()) return;*/
    address_t sectionAddress = addr;

    for(auto sec : segment->getContainsList()) {
        if(sec->hasHeader()) {
            LOG(0, "assign address 0x" << sectionAddress
                << "  to section [" << sec->getName() << "]");
            sec->getHeader()->setAddress(sectionAddress);
        }
        sectionAddress += sec->getContent()->getSize();
    }
}

size_t PagePaddingContent::getSize() const {
    size_t lastByte = previousSection->getOffset();
    if(previousSection->hasContent()) {
        lastByte += previousSection->getContent()->getSize();
    }

    if(isIsolatedPadding) {
        // how much data is needed to round from lastByte to a page boundary?
        size_t roundToPageBoundary = ((lastByte + PAGE_SIZE-1) & ~(PAGE_SIZE-1))
            - lastByte;
        LOG(0, "desiredOffset = " << desiredOffset << ", got = "
            << (lastByte + (roundToPageBoundary + desiredOffset) & (PAGE_SIZE-1)));
        return (roundToPageBoundary + desiredOffset) & (PAGE_SIZE-1);
    }
    else {
        static const address_t PAGE_SIZE = 0x1000;
        size_t size = (desiredOffset - (lastByte & (PAGE_SIZE-1)) + PAGE_SIZE) & (PAGE_SIZE-1);
        LOG(0, "add " << size << " bytes; desiredOffset = " << desiredOffset << ", got = "
            << ((lastByte + size) & (PAGE_SIZE-1)));
        return size;
    }
}

void PagePaddingContent::writeTo(std::ostream &stream) {
    stream << std::string(getSize(), '\0');
}

Section *RelocSectionContent::getTargetSection() {
    return outer->get();
}

RelocSectionContent::DeferredType *RelocSectionContent
    ::add(Chunk *source, Link *link) {

    if(auto v = dynamic_cast<DataOffsetLink *>(link)) {
        return addConcrete(dynamic_cast<Instruction *>(source), v);
    }
    else if(auto v = dynamic_cast<PLTLink *>(link)) {
        return addConcrete(dynamic_cast<Instruction *>(source), v);
    }
    else if(auto v = dynamic_cast<SymbolOnlyLink *>(link)) {
        return addConcrete(dynamic_cast<Instruction *>(source), v);
    }

    return nullptr;
}

RelocSectionContent::DeferredType *RelocSectionContent
    ::makeDeferredForLink(Instruction *source) {

    auto rela = new ElfXX_Rela();
    std::memset(rela, 0, sizeof(*rela));
    auto deferred = new DeferredType(rela);

    auto address = source->getAddress();
    int specialAddendOffset = 0;
#ifdef ARCH_X86_64
    if(auto sem = dynamic_cast<LinkedInstruction *>(source->getSemantic())) {
        address += sem->getDispOffset();
        specialAddendOffset = -(sem->getSize() - sem->getDispOffset());
    }
    else if(auto sem = dynamic_cast<ControlFlowInstruction *>(source->getSemantic())) {
        address += sem->getDispOffset();
        specialAddendOffset = -(sem->getSize() - sem->getDispOffset());
    }
#elif defined(ARCH_AARCH64)
#elif defined(ARCH_RISCV)
    assert(0); // XXX: no idea for now
#elif defined(ARCH_ARM)
    #error "how do we encode relocation offsets in instructions on arm?"
#else
#endif

    rela->r_offset  = address;
    rela->r_info    = 0;
    rela->r_addend  = specialAddendOffset;

    DeferredMap<address_t, ElfXX_Rela>::add(address, deferred);
    return deferred;
}

RelocSectionContent::DeferredType *RelocSectionContent
    ::addConcrete(Instruction *source, DataOffsetLink *link) {

    auto deferred = makeDeferredForLink(source);
    auto rela = deferred->getElfPtr();

    auto dest = static_cast<DataRegion *>(&*link->getTarget());  // assume != nullptr
    auto destAddress = link->getTargetAddress();

    rela->r_addend += destAddress - dest->getAddress();
    auto rodata = elfSpace->getElfMap()->findSection(".rodata")->getHeader();
    rela->r_addend -= rodata->sh_offset;  // offset of original .rodata

    auto symtab = (*sectionList)[".symtab"]->castAs<SymbolTableContent *>();
    deferred->addFunction([this, symtab] (ElfXX_Rela *rela) {
        size_t index = symtab->indexOfSectionSymbol(".rodata", sectionList);
        rela->r_info = ELFXX_R_INFO(index, R_X86_64_PC32);
    });

    return deferred;
}

RelocSectionContent::DeferredType *RelocSectionContent
    ::addConcrete(Instruction *source, PLTLink *link) {

    auto deferred = makeDeferredForLink(source);

#if 0  // ExternalSymbol can no longer be converted to a Symbol
    auto symtab = (*sectionList)[".symtab"]->castAs<SymbolTableContent *>();
    deferred->addFunction([this, symtab, link] (ElfXX_Rela *rela) {
        auto sit = SymbolInTable(SymbolInTable::TYPE_UNDEF,
            link->getPLTTrampoline()->getTargetSymbol());
        auto elfSym = symtab->find(sit);
        size_t index = symtab->indexOf(elfSym);
        if(index == (size_t)-1) LOG(1, "ERROR with target "
            << link->getPLTTrampoline()->getExternalSymbol()->getName());
        rela->r_info = ELFXX_R_INFO(index, R_X86_64_PLT32);
    });
#endif

    return deferred;
}

RelocSectionContent::DeferredType *RelocSectionContent
    ::addConcrete(Instruction *source, SymbolOnlyLink *link) {

    auto deferred = makeDeferredForLink(source);

    auto symtab = (*sectionList)[".symtab"]->castAs<SymbolTableContent *>();
    deferred->addFunction([this, symtab, link] (ElfXX_Rela *rela) {
        auto sit = SymbolInTable(SymbolInTable::TYPE_UNDEF,
            link->getSymbol());
        auto elfSym = symtab->find(sit);
        size_t index = symtab->indexOf(elfSym);
        rela->r_info = ELFXX_R_INFO(index, R_X86_64_PLT32);
    });

    return deferred;
}

Section *RelocSectionContent2::getTargetSection() {
    return other->get();
}

RelocSectionContent2::DeferredType *RelocSectionContent2
    ::addDataRef(address_t source, address_t target, DataSection *targetSection) {

    auto rela = new ElfXX_Rela();
    std::memset(rela, 0, sizeof(*rela));
    auto deferred = new DeferredType(rela);

    rela->r_offset  = source;
    rela->r_info    = 0;
    rela->r_addend  = target - targetSection->getAddress();

    auto name = targetSection->getName();
    auto symtab = (*sectionList)[".symtab"]->castAs<SymbolTableContent *>();
    deferred->addFunction([this, symtab, name] (ElfXX_Rela *rela) {
        size_t sectionSymbolIndex = symtab->indexOfSectionSymbol(
            name, sectionList);
        if(sectionSymbolIndex == (size_t)-1) {
            LOG(1, "can't find section symbol for [" << name << "]");
        }
        rela->r_info = ELF64_R_INFO(sectionSymbolIndex, R_X86_64_64);
    });

    DeferredMap<address_t, ElfXX_Rela>::add(source, deferred);
    return deferred;
}

DynamicSectionContent::DeferredType *DynamicSectionContent
    ::addPair(unsigned long key, std::function<address_t ()> generator) {

    auto deferred = new DeferredType(new DynamicDataPair(key));
    deferred->addFunction([generator] (DynamicDataPair *data) {
        data->setValue(static_cast<unsigned long>(generator()));
    });

    DeferredList<DynamicDataPair>::add(deferred);
    return deferred;
}

Section *DataRelocSectionContent::getTargetSection() {
    return outer->get();
}

static Symbol *makeSymbol(const std::string &targetName,
    Symbol::SymbolType symbolType, Symbol::BindingType bindType) {

    char *name = new char[targetName.length() + 1];
    std::strcpy(name, targetName.c_str());
    return new Symbol(0, 0, name, symbolType, bindType, 0, SHN_UNDEF);
}

DataRelocSectionContent::DeferredType *DataRelocSectionContent
    ::addUndefinedRef(DataVariable *var, const std::string &targetName) {

    auto rela = new ElfXX_Rela();
    std::memset(rela, 0, sizeof(*rela));
    auto deferred = new DeferredType(rela);

    rela->r_offset  = var->getAddress();
    rela->r_info    = 0;
    rela->r_addend  = 0;

    auto symbol = makeSymbol(targetName, Symbol::TYPE_OBJECT, Symbol::BIND_GLOBAL);
    auto symtab = (*sectionList)[".dynsym"]->castAs<SymbolTableContent *>();
    auto elfSym = symtab->addUndefinedSymbol(symbol);
    deferred->addFunction([this, symtab, elfSym, targetName] (ElfXX_Rela *rela) {
        LOG(1, "Creating undefined reloc for [" << targetName << "]");
        LOG(1, "    elfSym name offset " << elfSym->getElfPtr()->st_name);
        size_t index = symtab->indexOf(elfSym);
        LOG(1, "    index looks like " << index << " for elfSym " << elfSym);
        rela->r_info = ELF64_R_INFO(index, R_X86_64_GLOB_DAT);
    });

    DeferredMap<address_t, ElfXX_Rela>::add(var->getAddress(), deferred);
    return deferred;
}

DataRelocSectionContent::DeferredType *DataRelocSectionContent
    ::addDataRef(address_t source, address_t target, DataSection *targetSection) {

    auto rela = new ElfXX_Rela();
    std::memset(rela, 0, sizeof(*rela));
    auto deferred = new DeferredType(rela);

    rela->r_offset  = source;
    rela->r_info    = 0;
    rela->r_addend  = target; // - targetSection->getAddress();

    auto name = targetSection->getName();
    auto symtab = (*sectionList)[".symtab"]->castAs<SymbolTableContent *>();
    deferred->addFunction([this, symtab, name] (ElfXX_Rela *rela) {
        /*size_t sectionSymbolIndex = symtab->indexOfSectionSymbol(
            name, sectionList);
        if(sectionSymbolIndex == (size_t)-1) {
            LOG(1, "can't find section symbol for [" << name << "]");
        }*/
        rela->r_info = ELF64_R_INFO(0, R_X86_64_64);
    });

    DeferredMap<address_t, ElfXX_Rela>::add(source, deferred);
    return deferred;
}

DataRelocSectionContent::DeferredType *DataRelocSectionContent
    ::addDataFunctionRef(DataVariable *var, Function *function) {

    return addDataArbitraryRef(var, function->getAddress());

#if 0
    auto rela = new ElfXX_Rela();
    std::memset(rela, 0, sizeof(*rela));
    auto deferred = new DeferredType(rela);

    rela->r_offset  = source;
    rela->r_info    = 0;
    rela->r_addend  = 0;

    auto name = function->getName();
    auto symtab = (*sectionList)[".symtab"]->castAs<SymbolTableContent *>();
    deferred->addFunction([this, symtab, name] (ElfXX_Rela *rela) {
        /*size_t sectionSymbolIndex = symtab->indexOfSectionSymbol(
            name, sectionList);
        if(sectionSymbolIndex == (size_t)-1) {
            LOG(1, "can't find section symbol for [" << name << "]");
        }*/
        size_t index = symtab->indexOf(elfSym);
        rela->r_info = ELF64_R_INFO(0, R_X86_64_64);
    });

    DeferredMap<address_t, ElfXX_Rela>::add(source, deferred);
    return deferred;
#endif
}

DataRelocSectionContent::DeferredType *DataRelocSectionContent
    ::addDataAddressRef(address_t source, std::function<address_t ()> getTarget) {

    auto rela = new ElfXX_Rela();
    std::memset(rela, 0, sizeof(*rela));
    auto deferred = new DeferredType(rela);

    rela->r_offset  = source;
    rela->r_info    = ELF64_R_INFO(0, R_X86_64_64);
    rela->r_addend  = 0;

    deferred->addFunction([getTarget] (ElfXX_Rela *rela) {
        rela->r_addend = getTarget();
    });

    DeferredMap<address_t, ElfXX_Rela>::add(source, deferred);
    return deferred;
}

DataRelocSectionContent::DeferredType *DataRelocSectionContent
    ::addDataArbitraryRef(DataVariable *var, address_t targetAddress) {

    auto rela = new ElfXX_Rela();
    std::memset(rela, 0, sizeof(*rela));
    auto deferred = new DeferredType(rela);

    rela->r_offset  = var->getAddress();
    rela->r_info    = ELF64_R_INFO(0, R_X86_64_RELATIVE);
    rela->r_addend  = targetAddress;

    /*deferred->addFunction([this, symtab, name] (ElfXX_Rela *rela) {
        rela->r_info = ELF64_R_INFO(0, R_X86_64_64);
    });*/

    DeferredMap<address_t, ElfXX_Rela>::add(var->getAddress(), deferred);
    return deferred;
}

DataRelocSectionContent::DeferredType *DataRelocSectionContent
    ::addDataIFuncRef(DataVariable *var, address_t targetAddress) {

    auto rela = new ElfXX_Rela();
    std::memset(rela, 0, sizeof(*rela));
    auto deferred = new DeferredType(rela);

    rela->r_offset  = var->getAddress();
    rela->r_info    = ELF64_R_INFO(0, R_X86_64_IRELATIVE);
    rela->r_addend  = targetAddress;

    DeferredMap<address_t, ElfXX_Rela>::add(var->getAddress(), deferred);
    return deferred;
}

DataRelocSectionContent::DeferredType *DataRelocSectionContent
    ::addDataExternalRef(DataVariable *var, ExternalSymbol *extSym, Section *section,
        Module *module) {

    auto rela = new ElfXX_Rela();
    std::memset(rela, 0, sizeof(*rela));
    auto deferred = new DeferredType(rela);

    rela->r_offset  = var->getAddress();
    rela->r_info    = 0;
    rela->r_addend  = 0;

    auto targetName = extSym->getName();

    auto symtab = (*sectionList)[".dynsym"]->castAs<SymbolTableContent *>();
    SymbolTableContent::DeferredType *elfSym = nullptr;
    Symbol *symbol = nullptr;
    if(extSym->getLocalWeakInstance()) {
        address_t symbolAddress = 0;
        {
            auto sym = var->getTargetSymbol();
            auto section = module->getElfSpace()->getElfMap()->findSection(
                sym->getSectionIndex());
            auto dataSection = module->getDataRegionList()->findDataSection(
                section->getName());
            auto offset = sym->getAddress() - section->getVirtualAddress();
            //rela->r_offset = extSym->getAddress();
            symbolAddress = dataSection->getAddress() + offset;
        }
        char *name = new char[targetName.length() + 1];
        std::strcpy(name, targetName.c_str());
        symbol = new Symbol(
            symbolAddress, var->getSize(), name,
            var->getTargetSymbol()->getType(),
            var->getTargetSymbol()->getBind(), 0, 0);
        elfSym = symtab->addDataVarSymbol(var, symbol, symbolAddress,
            sectionList->indexOf(section));
    }
    else {
        symbol = makeSymbol(targetName, extSym->getType(), extSym->getBind());
        elfSym = symtab->addUndefinedSymbol(symbol);
    }
    deferred->addFunction([this, symtab, symbol, elfSym, targetName] (ElfXX_Rela *rela) {
        LOG(1, "Creating data reloc for [" << targetName << "]");
        LOG(1, "    elfSym name offset " << elfSym->getElfPtr()->st_name);
        size_t index = symtab->indexOf(elfSym);
        LOG(1, "    index looks like " << index << " for elfSym " << elfSym);
        if(symbol->getType() == Symbol::TYPE_FUNC) {
            rela->r_info = ELF64_R_INFO(index, R_X86_64_JUMP_SLOT);
        }
        else {
            rela->r_info = ELF64_R_INFO(index, R_X86_64_GLOB_DAT);
        }
    });

    DeferredMap<address_t, ElfXX_Rela>::add(var->getAddress(), deferred);
    return deferred;
}

DataRelocSectionContent::DeferredType *DataRelocSectionContent
    ::addCopyExternalRef(DataVariable *var, ExternalSymbol *extSym, Section *section) {

    auto rela = new ElfXX_Rela();
    std::memset(rela, 0, sizeof(*rela));
    auto deferred = new DeferredType(rela);

    rela->r_offset  = var->getAddress();
    rela->r_info    = 0;
    rela->r_addend  = 0;

    auto targetName = extSym->getName();

    char *name = new char[targetName.length() + 1];
    std::strcpy(name, targetName.c_str());

    auto symbol = new Symbol(
        var->getAddress(), var->getSize(), name,
        var->getTargetSymbol()->getType(),
        var->getTargetSymbol()->getBind(), 0, 0);
    auto symtab = (*sectionList)[".dynsym"]->castAs<SymbolTableContent *>();
    auto elfSym = symtab->addDataVarSymbol(var, symbol, var->getAddress(),
        sectionList->indexOf(section));

    deferred->addFunction([this, symtab, elfSym, targetName] (ElfXX_Rela *rela) {
        LOG(1, "Creating copy reloc for [" << targetName << "]");
        LOG(1, "    elfSym name offset " << elfSym->getElfPtr()->st_name);
        size_t index = symtab->indexOf(elfSym);
        LOG(1, "    index looks like " << index << " for elfSym " << elfSym);
        rela->r_info = ELF64_R_INFO(index, R_X86_64_COPY);
    });

    DeferredMap<address_t, ElfXX_Rela>::add(var->getAddress(), deferred);
    return deferred;
}

DataRelocSectionContent::DeferredType *DataRelocSectionContent
    ::addPLTRef(Section *gotPLT, PLTTrampoline *plt, size_t pltIndex) {

    auto rela = new ElfXX_Rela();
    std::memset(rela, 0, sizeof(*rela));
    auto deferred = new DeferredType(rela);

    rela->r_offset  = 0; // virtual address
    rela->r_info    = 0;
    rela->r_addend  = 0;

    auto extSymbol = plt->getExternalSymbol();
    auto symbol = makeSymbol(extSymbol->getName(),
        Symbol::TYPE_FUNC, extSymbol->getBind());
    auto symtab = (*sectionList)[".dynsym"]->castAs<SymbolTableContent *>();
    auto elfSym = symtab->addUndefinedSymbol(symbol);
    deferred->addFunction([this, gotPLT, plt, symtab, elfSym, extSymbol, pltIndex]
        (ElfXX_Rela *rela) {

        LOG(1, "Creating PLT reloc for [" << extSymbol->getName() << "] at 0x"
            << std::hex << plt->getAddress());
        LOG(1, "    elfSym name offset " << elfSym->getElfPtr()->st_name);
        size_t index = symtab->indexOf(elfSym);
        LOG(1, "    index looks like " << index << " for elfSym " << elfSym);
        if(plt->isPltGot()) {
            rela->r_info = ELF64_R_INFO(index, R_X86_64_GLOB_DAT);
        }
        else {
            rela->r_info = ELF64_R_INFO(index, R_X86_64_JUMP_SLOT);
        }

        rela->r_offset = gotPLT->getHeader()->getAddress()
            + (pltIndex * sizeof(address_t));
    });

    DeferredMap<address_t, ElfXX_Rela>::add(plt->getAddress(), deferred);
    return deferred;
}

DataRelocSectionContent::DeferredType *DataRelocSectionContent
    ::addTLSOffsetRef(address_t source, TLSDataOffsetLink *link) {

    auto rela = new ElfXX_Rela();
    std::memset(rela, 0, sizeof(*rela));
    auto deferred = new DeferredType(rela);

    rela->r_offset  = source;
    rela->r_info    = ELF64_R_INFO(0, R_X86_64_TPOFF64);
    rela->r_addend  = link->getRawTarget();

    DeferredMap<address_t, ElfXX_Rela>::add(source, deferred);
    return deferred;
}

DynamicSectionContent::DeferredType *DynamicSectionContent
    ::addPair(unsigned long key, unsigned long value) {

    auto deferred = new DeferredType(new DynamicDataPair(key, value));

    DeferredList<DynamicDataPair>::add(deferred);
    return deferred;
}

void InitArraySectionContent::writeTo(std::ostream &stream) {
    for(auto func : callbacks) {
        func();
    }
    for(auto func : array) {
        address_t address = func();
        LOG(0, "init_array value = " << address);
        std::string str{reinterpret_cast<char *>(&address), sizeof(address_t)};
        stream << str;
    }
}

/*
    Example PLT:
0000000000000610 <.plt>:
    610:   ff 35 92 09 20 00       push   QWORD PTR [rip+0x200992]
    616:   ff 25 94 09 20 00       jmp    QWORD PTR [rip+0x200994]
    61c:   0f 1f 40 00             nop    DWORD PTR [rax+0x0]

0000000000000620 <pthread_create@plt>:
    620:   ff 25 92 09 20 00       jmp    QWORD PTR [rip+0x200992]
    626:   68 00 00 00 00          push   0x0
    62b:   e9 e0 ff ff ff          jmp    610 <.plt>

*/

PLTCodeContent::DeferredType *PLTCodeContent::addEntry(
    PLTTrampoline *plt, size_t index) {

    auto entry = new PLTCodeEntry();
    auto deferred = new DeferredType(entry);

    if(index == 0) {
        std::memcpy(entry->data,
            "\xff\x35\x00\x00\x00\x00"
            "\xff\x25\x00\x00\x00\x00"
            "\x0f\x1f\x40\x00", 16);
    }
    else {
        std::memcpy(entry->data,
            "\xff\x25\x00\x00\x00\x00"
            "\x68\x00\x00\x00\x00"
            "\xe9\x00\x00\x00\x00", 16);
    }

    deferred->addFunction([this, index] (PLTCodeEntry *entry) {
#ifdef ARCH_X86_64
        address_t gotpltaddr = gotpltSection->getHeader()->getAddress();
        address_t pltaddr = pltSection->getHeader()->getAddress();

        const size_t gotPadding = 3;

        if(index == 0) {
            ssize_t pushOffset =
                (gotpltaddr + (1 * sizeof(address_t)))
                - (pltaddr + 6);
            ssize_t jmpOffset =
                (gotpltaddr + (2 * sizeof(address_t)))
                - (pltaddr + 6+6);

            *(int32_t *)(entry->data + PLTCodeEntry::Entry0Push) = pushOffset;
            *(int32_t *)(entry->data + PLTCodeEntry::Entry0Jmp) = jmpOffset;
        }
        else {
            ssize_t jmpOffset =
                (gotpltaddr + ((index-1+gotPadding) * sizeof(address_t)))
                - (pltaddr + index*0x10 + 6);
            ssize_t jmp2Offset = pltaddr - (pltaddr + index*0x10 + 6+5+5);

            *(int32_t *)(entry->data + PLTCodeEntry::EntryJmp) = jmpOffset;
            *(int32_t *)(entry->data + PLTCodeEntry::EntryPush) = index-1;
            *(int32_t *)(entry->data + PLTCodeEntry::EntryJmp2) = jmp2Offset;
        }
#else
    #error "PLT code generation needed for current platform!"
#endif
    });

    DeferredMap<PLTTrampoline *, PLTCodeEntry>::add(plt, deferred);
    return deferred;
}
