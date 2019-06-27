#include "pemap.h"
#include "log/log.h"

static const char *GetSymbolTableStorageClassName(std::uint8_t id);

PESection::PESection(int index, const std::string &name, address_t baseAddress,
    peparse::image_section_header header, peparse::bounded_buffer *buffer)
    : ExeSectionImpl(index, name, baseAddress, reinterpret_cast<char *>(buffer->buf)),
    header(header), buffer(buffer), characteristics(header.Characteristics) {

    
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

void PEMap::setup() {
    verifyPE();
    makeSectionMap();
    findDataDirectories();
    //findRelocations();
    //makeSegmentList();
    //makeVirtualAddresses();

    /*using namespace peparse;
    IterSec(peRef, [] (void *, VA sectionBase, std::string &name,
        image_section_header header, bounded_buffer *buffer) {

        LOG(1, "    section [" << name << "] at 0x" << std::hex << sectionBase);
        return 0;
    }, nullptr);*/

    /*IterSymbols(peRef, [] (void *,
        std::string &name,
        std::uint32_t &value,
        std::int16_t &sectionIndex,
        std::uint16_t &type,
        std::uint8_t &storageClass,
        std::uint8_t &auxSymCount) {

        LOG(1, "    symbol [" << name << "] at 0x" << std::hex << value
            << " class " << GetSymbolTableStorageClassName(storageClass));
        return 0;
    }, nullptr);*/

    /*IterRelocs(peRef, [] (void *,
        peparse::VA address, peparse::reloc_type type) {
        LOG(1, "    reloc 0x" << std::hex << address << " with type " << type);
        return 0;
    }, nullptr);*/
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

        bool isR = (header.Characteristics & IMAGE_SCN_MEM_READ) != 0;
        bool isW = (header.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        bool isX = (header.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

        auto section = new PESection(_this->getSectionCount(), name,
            sectionBase, header, buffer);
        LOG(1, "    section [" << name << "] at 0x" << std::hex << sectionBase
            << ", index " << section->getIndex() << ", perm " << "-R"[isR]
            << "-W"[isW] << "-X"[isX] << ", size "
            << buffer->bufLen << ", filesize " << header.SizeOfRawData);
        _this->addSection(section);
        return 0;
    }, this);
}

void PEMap::findDataDirectories() {
    using namespace peparse;
    data_directory *dir = peRef->peHeader.nt.OptionalHeader64.DataDirectory;

    {
        address_t importVA = dir[DIR_IMPORT].VirtualAddress;
        auto importEntry = getReadAddress<const import_dir_entry *>(importVA);
        for(size_t i = 0; i < dir[DIR_IMPORT].Size / sizeof(*importEntry); i++) {
            LOG(0, "importEntry ModuleNameRVA " << std::hex << importEntry[i].NameRVA);
            auto name = getReadAddress<const char *>(importEntry[i].NameRVA);
            if(name) LOG(0, "    with name [" << name << "]");

            auto funcTable = getReadAddress<address_t *>(importEntry[i].LookupTableRVA);
            while(funcTable && *funcTable) {
                auto funcName = getReadAddress<const char *>(*funcTable);
                if(funcName) {
                    funcName += 2;  // skip len of string at first 2 chars
                    LOG(0, "    func [" << funcName << "]"); 
                }
                funcTable++; 
            }
        }
    }
    
    address_t exportVA = dir[DIR_EXPORT].VirtualAddress;
    auto exportEntry = getReadAddress<const export_dir_table *>(exportVA);
    for(size_t i = 0; i < dir[DIR_EXPORT].Size / sizeof(*exportEntry); i++) {
        LOG(0, "exportEntry ModuleNameRVA " << std::hex << exportEntry[i].NameRVA);
        auto name = getReadAddress<const char *>(exportEntry[i].NameRVA);
        if(name) LOG(0, "    with name [" << name << "]");

        auto nameTable = getReadAddress<address_t *>(exportEntry[i].NamePointerRVA);
        auto addrTable = getReadAddress<address_t *>(exportEntry[i].ExportAddressTableRVA);
        auto ordinalTable = getReadAddress<unsigned short *>(exportEntry[i].OrdinalTableRVA);
        for(size_t j = 0; nameTable && nameTable[j]; j++) {
            auto funcName = getReadAddress<const char *>(nameTable[j]);
            if(funcName) {
                funcName += 2;  // skip len of string at first 2 chars
                LOG(0, "    func [" << funcName << "]"); 

                auto ordinal = ordinalTable[j];
                auto addr = getReadAddress<const char *>(addrTable[ordinal]);
                LOG(0, "    at addr 0x" << std::hex << addr);
            }
        }
    }
}

#if 0
void PEMap::findRelocations() {
    IterRelocs(peRef, [] (void *,
        peparse::VA address, peparse::reloc_type type) {

        // pe-parse adds the base address to section addresses, we undo this.
        nt_header_32 *nthdr = &_this->peRef->peHeader.nt;
        address_t baseAddress = nthdr->OptionalHeader64.ImageBase;
        address -= baseAddress;

        LOG(1, "    reloc 0x" << std::hex << address << " with type " << type);
        return 0;
    }, nullptr);
}
#endif

address_t PEMap::getEntryPoint() const {
    peparse::VA va;
    GetEntryPoint(peRef, va);
    return static_cast<address_t>(va);
}

address_t PEMap::getSectionAlignment() const {
    return peRef->peHeader.nt.OptionalHeader64.SectionAlignment;
}

PESection *PEMap::findSectionContaining(address_t address) const {
    for(auto section : getSectionList()) {
        if(address >= section->getVirtualAddress()
            && address < section->getVirtualAddress() + section->getSize()) {
            
            return section;
        }
    }
    return nullptr;
}

#if 0
char *PEMap::getReadAddress(address_t virtualAddress) const {
    auto section = findSectionContaining(virtualAddress);
    if(!section) return nullptr;

    return section->getReadAddress()
        + (virtualAddress - section->getVirtualAddress());
}
#endif

static const char *GetSymbolTableStorageClassName(std::uint8_t id) {
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
