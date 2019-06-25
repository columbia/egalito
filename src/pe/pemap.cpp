#include "pemap.h"
#include "log/log.h"

PESection::PESection(int index, const std::string &name, address_t baseAddress,
    peparse::image_section_header header, peparse::bounded_buffer *buffer)
    : ExeSectionImpl(index, name, baseAddress, reinterpret_cast<char *>(buffer->buf)),
    buffer(buffer) {

    
}

PEMap::PEMap(const std::string &filename) : peRef(nullptr) {
    parsePE(filename);
    setup();
}

PEMap::~PEMap() {
    peparse::DestructParsedPE(peRef);
}

void PEMap::throwError(const std::string &err) {
    LOG(0, "PEMap error: " << err << ": "
        << peparse::GetPEErrString() << " ("
        << peparse::GetPEErr() << ") at "
        << peparse::GetPEErrLoc());

    throw "PEMap error parsing PE file";
}

bool PEMap::isPE(const std::string &filename) {
    try {
        PEMap pe(filename);
    }
    catch(const char *error) {
        return false;
    }

    return true;
}

const char *GetSymbolTableStorageClassName(std::uint8_t id) {
  switch (id) {
    case peparse::IMAGE_SYM_CLASS_END_OF_FUNCTION:
      return "CLASS_END_OF_FUNCTION";
    case peparse::IMAGE_SYM_CLASS_NULL:
      return "CLASS_NULL";
    case peparse::IMAGE_SYM_CLASS_AUTOMATIC:
      return "CLASS_AUTOMATIC";
    case peparse::IMAGE_SYM_CLASS_EXTERNAL:
      return "CLASS_EXTERNAL";
    case peparse::IMAGE_SYM_CLASS_STATIC:
      return "CLASS_STATIC";
    case peparse::IMAGE_SYM_CLASS_REGISTER:
      return "CLASS_REGISTER";
    case peparse::IMAGE_SYM_CLASS_EXTERNAL_DEF:
      return "CLASS_EXTERNAL_DEF";
    case peparse::IMAGE_SYM_CLASS_LABEL:
      return "CLASS_LABEL";
    case peparse::IMAGE_SYM_CLASS_UNDEFINED_LABEL:
      return "CLASS_UNDEFINED_LABEL";
    case peparse::IMAGE_SYM_CLASS_MEMBER_OF_STRUCT:
      return "CLASS_MEMBER_OF_STRUCT";
    case peparse::IMAGE_SYM_CLASS_ARGUMENT:
      return "CLASS_ARGUMENT";
    case peparse::IMAGE_SYM_CLASS_STRUCT_TAG:
      return "CLASS_STRUCT_TAG";
    case peparse::IMAGE_SYM_CLASS_MEMBER_OF_UNION:
      return "CLASS_MEMBER_OF_UNION";
    case peparse::IMAGE_SYM_CLASS_UNION_TAG:
      return "CLASS_UNION_TAG";
    case peparse::IMAGE_SYM_CLASS_TYPE_DEFINITION:
      return "CLASS_TYPE_DEFINITION";
    case peparse::IMAGE_SYM_CLASS_UNDEFINED_STATIC:
      return "CLASS_UNDEFINED_STATIC";
    case peparse::IMAGE_SYM_CLASS_ENUM_TAG:
      return "CLASS_ENUM_TAG";
    case peparse::IMAGE_SYM_CLASS_MEMBER_OF_ENUM:
      return "CLASS_MEMBER_OF_ENUM";
    case peparse::IMAGE_SYM_CLASS_REGISTER_PARAM:
      return "CLASS_REGISTER_PARAM";
    case peparse::IMAGE_SYM_CLASS_BIT_FIELD:
      return "CLASS_BIT_FIELD";
    case peparse::IMAGE_SYM_CLASS_BLOCK:
      return "CLASS_BLOCK";
    case peparse::IMAGE_SYM_CLASS_FUNCTION:
      return "CLASS_FUNCTION";
    case peparse::IMAGE_SYM_CLASS_END_OF_STRUCT:
      return "CLASS_END_OF_STRUCT";
    case peparse::IMAGE_SYM_CLASS_FILE:
      return "CLASS_FILE";
    case peparse::IMAGE_SYM_CLASS_SECTION:
      return "CLASS_SECTION";
    case peparse::IMAGE_SYM_CLASS_WEAK_EXTERNAL:
      return "CLASS_WEAK_EXTERNAL";
    case peparse::IMAGE_SYM_CLASS_CLR_TOKEN:
      return "CLASS_CLR_TOKEN";
    default:
      return nullptr;
  }
}

void PEMap::setup() {
    verifyPE();
    makeSectionMap();
    //makeSegmentList();
    //makeVirtualAddresses();

    /*using namespace peparse;
    IterSec(peRef, [] (void *, VA sectionBase, std::string &name,
        image_section_header header, bounded_buffer *buffer) {

        LOG(1, "    section [" << name << "] at 0x" << std::hex << sectionBase);
        return 0;
    }, nullptr);*/

    IterSymbols(peRef, [] (void *,
        std::string &name,
        std::uint32_t &value,
        std::int16_t &sectionIndex,
        std::uint16_t &type,
        std::uint8_t &storageClass,
        std::uint8_t &auxSymCount) {

        LOG(1, "    symbol [" << name << "] at 0x" << std::hex << value
            << " class " << GetSymbolTableStorageClassName(storageClass));
        return 0;
    }, nullptr);
}

void PEMap::parsePE(const std::string &filename) {
    CLOG(1, "creating PEMap for file [%s]", filename.c_str());
    peRef = peparse::ParsePEFromFile(filename.c_str());
    if(!peRef) throwError("ParsePEFromFile");

    verifyPE();
}

void PEMap::verifyPE() {
    if(peRef->peHeader.nt.FileHeader.Machine != peparse::IMAGE_FILE_MACHINE_AMD64) {
        throwError("exe is not 64-bit");
    }
}

void PEMap::makeSectionMap() {
    using namespace peparse;
    IterSec(peRef, [] (void *data, VA sectionBase, std::string &name,
        image_section_header header, bounded_buffer *buffer) {
        auto _this = static_cast<PEMap *>(data);

        // pe-parse adds the base address to section addresses, we undo this.
        nt_header_32 *nthdr = &_this->peRef->peHeader.nt;
        address_t baseAddress = nthdr->OptionalHeader64.ImageBase;
        sectionBase -= baseAddress;

        auto section = new PESection(_this->getSectionCount(), name,
            sectionBase, header, buffer);
        LOG(1, "    section [" << name << "] at 0x" << std::hex << sectionBase << ", index " << section->getIndex());
        _this->addSection(section);
        return 0;
    }, this);
}

address_t PEMap::getEntryPoint() const {
    peparse::VA va;
    GetEntryPoint(peRef, va);
    return static_cast<address_t>(va);
}

#if 0
void PEMap::makeSegmentList() {
    char *charmap = static_cast<char *>(map);
    ElfXX_Ehdr *header = (ElfXX_Ehdr *)map;
    ElfXX_Phdr *pheader = (ElfXX_Phdr *)(charmap + header->e_phoff);

    for(int i = 0; i < header->e_phnum; i ++) {
        ElfXX_Phdr *phdr = &pheader[i];
        segmentList.push_back(static_cast<void *>(phdr));
    }
}

void PEMap::makeVirtualAddresses() {
    baseAddress = 0;
    copyBase = 0;
    interpreter = nullptr;
    char *charmap = static_cast<char *>(map);

    for(std::map<std::string, ElfSection *>::iterator it = sectionMap.begin(); it != sectionMap.end(); ++it) {
        auto section = it->second;
        auto header = section->getHeader();
        section->setReadAddress((address_t)charmap + header->sh_offset);
        section->setVirtualAddress(header->sh_addr);
    }

    this->strtab = getSectionReadPtr<const char *>(".strtab");
    this->dynstr = getSectionReadPtr<const char *>(".dynstr");

    if (isObjectFile()) {
        copyBase = (address_t)(charmap);
        rwCopyBase = (address_t)(charmap);

        sectionMap[".data"]->setVirtualAddress(0x20000);
        sectionMap[".bss"]->setVirtualAddress(sectionMap[".data"]->getVirtualAddress() + sectionMap[".data"]->getHeader()->sh_size);
        sectionMap[".rodata"]->setVirtualAddress(sectionMap[".bss"]->getVirtualAddress() + sectionMap[".bss"]->getHeader()->sh_size);
        return;
    }

    ElfXX_Ehdr *header = (ElfXX_Ehdr *)map;
    ElfXX_Phdr *pheader = (ElfXX_Phdr *)(charmap + header->e_phoff);

    for(int i = 0; i < header->e_phnum; i ++) {
        ElfXX_Phdr *phdr = &pheader[i];

        if(phdr->p_type == PT_LOAD && phdr->p_flags == (PF_R | PF_X)) {
            copyBase = (address_t)(charmap + phdr->p_offset - phdr->p_vaddr);
        }
        if(phdr->p_type == PT_LOAD && phdr->p_flags == (PF_R | PF_W)) {
            rwCopyBase = (address_t)(charmap + phdr->p_offset - phdr->p_vaddr);
        }
        if(phdr->p_type == PT_INTERP) {
            interpreter = charmap + phdr->p_offset;
        }
    }
}

std::vector<void *> PEMap::findSectionsByType(int type) const {
    std::vector<void *> sections;
    ElfXX_Shdr sCast;

    char *charmap = static_cast<char *>(map);
    ElfXX_Ehdr *header = (ElfXX_Ehdr *)map;
    ElfXX_Shdr *sheader = (ElfXX_Shdr *)(charmap + header->e_shoff);
    for(int i = 0; i < header->e_shnum; i ++) {
        ElfXX_Shdr *s = &sheader[i];

        if(s->sh_type == static_cast<decltype(sCast.sh_type)>(type)) {
            sections.push_back(static_cast<void *>(s));
        }
    }

    return std::move(sections);
}

std::vector<void *> PEMap::findSectionsByFlag(long flag) const {
    std::vector<void *> sections;

    char *charmap = static_cast<char *>(map);
    ElfXX_Ehdr *header = (ElfXX_Ehdr *)map;
    ElfXX_Shdr *sheader = (ElfXX_Shdr *)(charmap + header->e_shoff);
    for(int i = 0; i < header->e_shnum; i ++) {
        ElfXX_Shdr *s = &sheader[i];

        if(s->sh_flags & flag) {
            sections.push_back(static_cast<void *>(s));
        }
    }

    return sections;
}


address_t ElfSection::convertOffsetToVA(size_t offset) {
    return virtualAddress + offset;
}

address_t ElfSection::convertVAToOffset(address_t va) {
    return va - virtualAddress;
}

size_t PEMap::getEntryPoint() const {
    ElfXX_Ehdr *header = (ElfXX_Ehdr *)map;
    return header->e_entry;
}

bool PEMap::isExecutable() const {
    ElfXX_Ehdr *header = (ElfXX_Ehdr *)map;
    return header->e_type == ET_EXEC;
}

bool PEMap::isSharedLibrary() const {
    ElfXX_Ehdr *header = (ElfXX_Ehdr *)map;
    return header->e_type == ET_DYN;
}

bool PEMap::isObjectFile() const {
    ElfXX_Ehdr *header = (ElfXX_Ehdr *)map;
    return header->e_type == ET_REL;
}

bool PEMap::isDynamic() const {
    return findSection(".dynamic") != nullptr;
}

bool PEMap::hasRelocations() const {
    return !findSectionsByType(SHT_RELA).empty();
    //return findSection(".rela.text") != nullptr;
}
#endif
