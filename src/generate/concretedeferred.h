#ifndef EGALITO_GENERATE_CONCRETE_DEFERRED_H
#define EGALITO_GENERATE_CONCRETE_DEFERRED_H

#include <vector>
#include "deferred.h"
#include "integerdeferred.h"
#include "chunk/link.h"
#include "elf/elfxx.h"

class Section;
class SectionRef;
class Symbol;
class Function;
class DataVariable;
class Instruction;
class ElfSpace;
class Chunk;
class SectionList;

class SymbolInTable {
public:
    enum type_t {
        TYPE_NULL,
        TYPE_SECTION,
        TYPE_PLT,
        TYPE_LOCAL,
        TYPE_UNDEF,
        TYPE_GLOBAL,
    };
private:
    type_t type;
    Symbol *sym;
    size_t tableIndex;  // for ordering .dynsym
public:
    SymbolInTable(type_t type = TYPE_NULL, Symbol *sym = nullptr)
        : type(type), sym(sym), tableIndex(0) {}
    bool operator < (const SymbolInTable &other) const;
    bool operator == (const SymbolInTable &other) const;
    Symbol *get() const { return sym; }
    std::string getName() const;
    void setTableIndex(size_t index) { tableIndex = index; }
};

/** Symbol table, either .strtab or .dynstr. The ordering of symbols
    is determined by SymbolInTable::operator {<,==}.
*/
class SymbolTableContent : public DeferredMap<SymbolInTable, ElfXX_Sym> {
public:
    typedef DeferredValueImpl<ElfXX_Sym> DeferredType;
private:
    DeferredStringList *strtab;
    std::vector<DeferredType *> sectionSymbols;
    int firstGlobalIndex;
public:
    SymbolTableContent(DeferredStringList *strtab)
        : strtab(strtab), firstGlobalIndex(0) {}

    void addNullSymbol();
    void addSectionSymbol(Symbol *sym);
    DeferredType *addSymbol(Function *func, Symbol *sym);
    DeferredType *addDataVarSymbol(DataVariable *var, Symbol *sym,
        address_t address, size_t section = SHN_UNDEF);
    DeferredType *addPLTSymbol(PLTTrampoline *plt, Symbol *sym);
    DeferredType *addUndefinedSymbol(Symbol *sym);

    size_t indexOfSectionSymbol(const std::string &section,
        SectionList *sectionList);
    int getFirstGlobalIndex() const { return firstGlobalIndex; }
public:
    static SymbolInTable::type_t getTypeFor(Function *func);
};

class ShdrTableContent : public DeferredMap<Section *, ElfXX_Shdr> {
public:
    typedef DeferredValueImpl<ElfXX_Shdr> DeferredType;
public:
    DeferredType *add(Section *section);
};

class SegmentInfo {
private:
    ElfXX_Word type;
    ElfXX_Word flags;
    address_t alignment;
    size_t additionalMemSize;
    std::vector<Section *> containsList;
public:
    SegmentInfo(ElfXX_Word type, ElfXX_Word flags, address_t alignment)
        : type(type), flags(flags), alignment(alignment), additionalMemSize(0) {}

    void setAdditionalMemSize(size_t a) { additionalMemSize = a; }
    void addContains(Section *section) { containsList.push_back(section); }

    ElfXX_Word getType() const { return type; }
    ElfXX_Word getFlags() const { return flags; }
    address_t getAlignment() const { return alignment; }
    size_t getAdditionalMemSize() const { return additionalMemSize; }
    std::vector<Section *> &getContainsList() { return containsList; }
};

class PhdrTableContent : public DeferredMap<SegmentInfo *, ElfXX_Phdr> {
public:
    typedef DeferredValueImpl<ElfXX_Phdr> DeferredType;
private:
    SectionList *sectionList;
public:
    PhdrTableContent(SectionList *sectionList) : sectionList(sectionList) {}

    DeferredType *add(SegmentInfo *segment);
    DeferredType *add(SegmentInfo *segment, address_t address);
    void assignAddressesToSections(SegmentInfo *segment, address_t addr);
};

class PagePaddingContent : public DeferredValue {
private:
    //static const address_t PAGE_SIZE = 0x200000;
    static const address_t PAGE_SIZE = 0x1000;
private:
    Section *previousSection;
    address_t desiredOffset;
    bool isIsolatedPadding;  // true if data outside map region should be null
public:
    PagePaddingContent(Section *previousSection, address_t desiredOffset = 0,
        bool isIsolatedPadding = true) : previousSection(previousSection),
        desiredOffset(desiredOffset), isIsolatedPadding(isIsolatedPadding) {}

    virtual size_t getSize() const;
    virtual void writeTo(std::ostream &stream);
};

class RelocSectionContent : public DeferredMap<address_t, ElfXX_Rela> {
public:
    typedef DeferredValueImpl<ElfXX_Rela> DeferredType;
private:
    SectionRef *outer;
    SectionList *sectionList;
    ElfSpace *elfSpace;
public:
    RelocSectionContent(SectionRef *outer, SectionList *sectionList,
        ElfSpace *elfSpace) : outer(outer), sectionList(sectionList),
        elfSpace(elfSpace) {}

    Section *getTargetSection();

    DeferredType *add(Chunk *source, Link *link);
private:
    DeferredType *makeDeferredForLink(Instruction *source);
    DeferredType *addConcrete(Instruction *source, DataOffsetLink *link);
    DeferredType *addConcrete(Instruction *source, PLTLink *link);
    DeferredType *addConcrete(Instruction *source, SymbolOnlyLink *link);
};

class DataSection;
class RelocSectionContent2 : public DeferredMap<address_t, ElfXX_Rela> {
public:
    typedef DeferredValueImpl<ElfXX_Rela> DeferredType;
private:
    SectionList *sectionList;
    SectionRef *other;
public:
    RelocSectionContent2(SectionList *sectionList, SectionRef *other)
        : sectionList(sectionList), other(other) {}

    Section *getTargetSection();

    DeferredType *addDataRef(address_t source, address_t target,
        DataSection *targetSection);
};

class DataVariable;
class DataRelocSectionContent : public DeferredMap<address_t, ElfXX_Rela> {
public:
    typedef DeferredValueImpl<ElfXX_Rela> DeferredType;
private:
    SectionRef *outer;
    SectionList *sectionList;
public:
    DataRelocSectionContent(SectionRef *outer, SectionList *sectionList)
        : outer(outer), sectionList(sectionList) {}

    Section *getTargetSection();

    DeferredType *addUndefinedRef(DataVariable *var,
        const std::string &targetName);
    DeferredType *addDataRef(address_t source, address_t target,
        DataSection *targetSection);
    DeferredType *addDataFunctionRef(DataVariable *var, Function *function);
    DeferredType *addDataAddressRef(address_t source,
        std::function<address_t ()> getTarget);
    DeferredType *addDataArbitraryRef(DataVariable *var, address_t targetAddress);
    DeferredType *addDataExternalRef(DataVariable *var,
        ExternalSymbol *extSym, Section *section, Module *module);
    DeferredType *addCopyExternalRef(DataVariable *var,
        ExternalSymbol *extSym, Section *section);
    DeferredType *addPLTRef(Section *gotPLT, PLTTrampoline *plt, size_t pltIndex);

    DeferredType *addTLSOffsetRef(address_t source, TLSDataOffsetLink *link);
};

class DynamicDataPair {
private:
    unsigned long key;
    unsigned long value;
public:
    DynamicDataPair(unsigned long key, unsigned long value = 0)
        : key(key), value(value) {}
    unsigned long getKey() const { return key; }
    unsigned long getValue() const { return value; }
    void setKey(unsigned long key) { this->key = key; }
    void setValue(unsigned long value) { this->value = value; }
};

class DynamicSectionContent : public DeferredList<DynamicDataPair> {
public:
    typedef DeferredValueImpl<DynamicDataPair> DeferredType;

    DeferredType *addPair(unsigned long key,
        std::function<address_t ()> generator);
    DeferredType *addPair(unsigned long key, unsigned long value);
};

class InitArraySectionContent : public DeferredValue {
private:
    std::vector<std::function<address_t ()>> array;
    std::vector<std::function<void ()>> callbacks;
public:
    void addPointer(std::function<address_t ()> func) { array.push_back(func); }
    void addCallback(std::function<void ()> func) { callbacks.push_back(func); }
    virtual size_t getSize() const { return array.size() * sizeof(address_t); }
    virtual void writeTo(std::ostream &stream);
};

#ifdef ARCH_X86_64
struct PLTCodeEntry {
    char data[16];

    enum {
        Entry0Push = 2,
        Entry0Jmp = 6+2,
        EntryJmp = 2,
        EntryPush = 6+1,
        EntryJmp2 = 6+5+1
    };
} __attribute__((packed));
#else
    #error "Need PLTCodeEntry for current platform!"
#endif

class PLTCodeContent : public DeferredMap<PLTTrampoline *, PLTCodeEntry> {
public:
    typedef DeferredValueImpl<PLTCodeEntry> DeferredType;
private:
    Section *gotpltSection;
    Section *pltSection;
public:
    PLTCodeContent(Section *gotpltSection, Section *pltSection)
        : gotpltSection(gotpltSection), pltSection(pltSection) {}

    DeferredType *addEntry(PLTTrampoline *plt, size_t index);
};

class GnuHashSectionContent : public DeferredIntegerList {
public:
    using DeferredIntegerList::DeferredIntegerList;
};

class TBSSContent : public DeferredString {
private:
    size_t memSize;
public:
    TBSSContent(size_t memSize) : DeferredString(""), memSize(memSize) {}

    size_t getMemSize() const { return memSize; }
};

#endif
