#include <cassert>
#include <iomanip>
#include "dataregion.h"
#include "link.h"
#include "position.h"
#include "concrete.h"
#include "serializer.h"
#include "instr/serializer.h"
#include "visitor.h"
#include "chunk/aliasmap.h"
#include "elf/elfspace.h"
#include "operation/find.h"
#include "operation/mutator.h"
#include "util/streamasstring.h"
#include "log/log.h"
#include "log/temp.h"
#include "chunk/dump.h"

DataVariable *DataVariable::create(Module *module, address_t address,
    Link *dest, Symbol *symbol) {

    auto region = module->getDataRegionList()->findRegionContaining(address);
    assert(region != nullptr);
    auto section = region->findDataSectionContaining(address);
    assert(section != nullptr);

    return DataVariable::create(section, address, dest, symbol);
}

DataVariable *DataVariable::create(DataSection *section, address_t address,
    Link *dest, Symbol *symbol) {

    assert(section != nullptr);
    if(auto var = section->findVariable(address)) {
        LOG(10, "variable already exists for " << address);
        return var;
    }
    auto var = new DataVariable(section, address, dest);
    if(symbol) {
        var->setName(symbol->getName());
    }
    //ChunkMutator(section).append(var);
    var->setParent(section);
    section->getChildren()->add(var);

    assert(section->findVariable(address));

    return var;
}

DataVariable::DataVariable(DataSection *section, address_t address, Link *dest)
    : dest(dest), size(sizeof(address_t)) {

    assert(section != nullptr);
    assert(section->contains(address));

    auto offset = address - section->getAddress();
    this->setPosition(new AbsoluteOffsetPosition(this, offset));
}

void DataVariable::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    writer.writeID(op.assign(getParent()));
    writer.write<address_t>(
        static_cast<AbsoluteOffsetPosition *>(getPosition())->getOffset());
    writer.writeString(name);

    if(op.isLocalModuleOnly()) {
        // not yet implemented, should serialize if in this module, otherwise
        // create an external symbol
    }
    else {
        LinkSerializer(op).serialize(dest, writer);
    }
    writer.write<size_t>(size);
}

bool DataVariable::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    setParent(op.lookup(reader.readID()));
    setPosition(new AbsoluteOffsetPosition(this, reader.read<address_t>()));
    name = reader.readString();
    dest = LinkSerializer(op).deserialize(reader);
    setDest(dest);
    setSize(reader.read<size_t>());
    return reader.stillGood();
}

DataSection::DataSection(ElfMap *elfMap, address_t segmentAddress,
    ElfXX_Shdr *shdr) {

    name = std::string(elfMap->getSHStrtab() + shdr->sh_name);
    alignment = shdr->sh_addralign;
    originalOffset = shdr->sh_addr - segmentAddress; //shdr->sh_addr - phdr->p_vaddr;
    setPosition(new AbsoluteOffsetPosition(this, originalOffset));
    setSize(shdr->sh_size);

    // !!! there is probably a better way to determine the type!
    if(shdr->sh_type == SHT_NOBITS) type = TYPE_BSS;
    else if(shdr->sh_type == SHT_INIT_ARRAY) type = TYPE_INIT_ARRAY;
    else if(shdr->sh_type == SHT_FINI_ARRAY) type = TYPE_FINI_ARRAY;
    else if(shdr->sh_type == SHT_PROGBITS) {
        if(name.substr(0, 7) == "__libc_") type = TYPE_DATA;
        else if(shdr->sh_flags & SHF_EXECINSTR) type = TYPE_CODE;
        else if(name == ".data" || name == ".tdata" || name == ".rodata"
            || name == ".got" || name == ".got.plt"
            /*|| name == ".data..percpu"*/ || name == ".init.data"
            || name == ".data_nosave" || name == ".altinstr_aux"
            || name == ".vvar") {

            type = TYPE_DATA;
        }
        else type = TYPE_UNKNOWN;

        if (type == TYPE_DATA) {
            LOG(0, "[" << name << "] is a data section");
        }
    }
    else type = TYPE_UNKNOWN;
}

std::string DataSection::getName() const {
    return name;
}

bool DataSection::contains(address_t address) {
    return getRange().contains(address);
}

DataVariable *DataSection::findVariable(const std::string &name) {
#if 1
    return CIter::named(this)->find(name);
#else
    for(auto var : CIter::children(this)) {
        if(var->getName() == name) return var;
    }
    return nullptr;
#endif
}

DataVariable *DataSection::findVariable(address_t address) {
#if 1
    return CIter::spatial(this)->find(address);
#else
    for(auto var : CIter::children(this)) {
        if(var->getAddress() == address) return var;
    }
    return nullptr;
#endif
}

void DataSection::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    writer.write<size_t>(getSize());
    writer.writeString(name);
    writer.write(alignment);
    writer.write(originalOffset);
    writer.write<uint8_t>(type);

    op.serializeChildren(this, writer);
}

bool DataSection::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    setSize(reader.read<size_t>());
    name = reader.readString();
    reader.readInto(alignment);
    reader.readInto(originalOffset);
    type = static_cast<Type>(reader.read<uint8_t>());

    setPosition(new AbsoluteOffsetPosition(this, originalOffset));

    op.deserializeChildren(this, reader);
    return reader.stillGood();
}

void DataSection::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

DataRegion::DataRegion(ElfMap *elfMap, ElfXX_Phdr *phdr) {
    setPosition(new AbsolutePosition(phdr->p_vaddr));
    size = phdr->p_memsz;   // size must not be calculated from children
    originalAddress = getAddress();
    permissions = phdr->p_flags;
    alignment = phdr->p_align;

    auto readAddress = elfMap->getCharmap() + phdr->p_offset;
    dataBytes.assign(readAddress, phdr->p_filesz);
    // note: dataBytes may store less than getSize(). Padded with zeros.
}

void DataRegion::saveDataBytes(bool captureUninitializedData) {
    const char *address = reinterpret_cast<const char *>(getAddress());

    // In the case of uninitialized/zeroed .bss data, if we are saving the
    // data bytes then we may want to capture any modifications that were
    // made e.g. by links or relocations. Essentially, we convert it to
    // initialized data.
    size_t size = captureUninitializedData ? getSize() : dataBytes.size();

    dataBytes.assign(address, size);
}

std::string DataRegion::getName() const {
    StreamAsString stream;
    stream << "region-0x" << std::hex << originalAddress;
    return stream;
}

bool DataRegion::contains(address_t address) {
    return getRange().contains(address);
}

void DataRegion::updateAddressFor(address_t baseAddress) {
    LOG(1, "UPDATE address for DataRegion from " << std::hex
        << getAddress() << " to " << (baseAddress + originalAddress));
    getPosition()->set(baseAddress + originalAddress);
}

DataVariable *DataRegion::findVariable(const std::string &name) {
    for(auto section : CIter::children(this)) {
        if(auto var = section->findVariable(name)) {
            return var;
        }
    }
    return nullptr;
}

DataVariable *DataRegion::findVariable(address_t address) {
    for(auto section : CIter::children(this)) {
        if(auto var = section->findVariable(address)) {
            return var;
        }
    }
    return nullptr;
}

DataSection *DataRegion::findDataSectionContaining(address_t address) {
    for(auto ds : CIter::children(this)) {
        if(ds->contains(address)) {
            return ds;
        }
    }
    return nullptr;
}

DataSection *DataRegion::findDataSection(const std::string &name) {
    return CIter::named(this)->find(name);
}

void DataRegion::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    writer.write(getAddress());
    writer.write(getSize());
    writer.write(originalAddress);
    writer.write(permissions);
    writer.write(alignment);
    writer.writeBytes<uint64_t>(dataBytes);

    op.serializeChildren(this, writer);
}

bool DataRegion::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    setParent(nullptr);
    address_t address = reader.read<address_t>();
    setPosition(new AbsolutePosition(address));
    reader.readInto(this->size);
    reader.readInto(this->originalAddress);
    reader.readInto(this->permissions);
    reader.readInto(this->alignment);
    dataBytes = std::move(reader.readBytes<uint64_t>());

    op.deserializeChildren(this, reader);
    return reader.stillGood();
}

void DataRegion::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

std::string TLSDataRegion::getName() const {
    return "region-TLS";
}

void TLSDataRegion::setBaseAddress(address_t baseAddress) {
    LOG(1, "set base address for TLSDataRegion from " << std::hex
        << getAddress() << " to " << baseAddress);
    getPosition()->set(baseAddress);
}

bool TLSDataRegion::containsData(address_t address) {
#if 1
    auto size = getSizeOfInitializedData();  // this is filesize
    return Range(getAddress(), size).contains(address);
#else
    /*
     * When iterating through relocations in the source elf file, there will be
     * some relocations in the uninitialized (.tbss) portion of the TLS. We want
     * to associate those relocations (and hence data variables) with the TLS
     * rather than the load segment which occupies the same virtual addresses as
     * the TLS. So, pretend the size of TLS is the full memsize.
     */
    return getRange().contains(address);  // getSize() is memsize
#endif
}

void TLSDataRegion::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    DataRegion::serialize(op, writer);
    writer.write(tlsOffset);
}

bool TLSDataRegion::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    DataRegion::deserialize(op, reader);
    reader.readInto(tlsOffset);

    return reader.stillGood();
}

void DataRegionList::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

Link *DataRegionList::createDataLink(address_t target, Module *module,
    bool isRelative) {

    auto region = findRegionContaining(target);
    if(region) {
        LOG(11, "    region is " << region->getName());
        auto dsec = CIter::spatial(region)->findContaining(target);
        if(dsec) {
            LOG(11, "    section is " << dsec->getName());
            if(dsec->getType() == DataSection::TYPE_CODE) {
                // This should only exists for section relative relocation.
                // A tricky case is where it is relative to a symbol which
                // at the start address of the section
#if 1
                if(ChunkFind().findInnermostAt(
                    module->getFunctionList(), target)) {

                    LOG(1, "is this a hand-crafted jump table? " << target);
                    return nullptr;
                }
                else {
#ifdef ARCH_AARCH64
                    // this will very likely to result in a too-far
                    // link for AARCH64.
                    LOG(9, "is this a LITERAL? " << target);
#endif
                    return nullptr;
                }
#endif
            }
            auto base = dsec->getAddress();
            LOG(10, "" << target << " has offset " << (target - base));
            if(isRelative) {
                return new DataOffsetLink(dsec, target - base,
                    Link::SCOPE_WITHIN_MODULE);
            }
            else {
                return new AbsoluteDataLink(dsec, target - base,
                    Link::SCOPE_WITHIN_MODULE);
            }
        }
    }

    return nullptr;
}

DataRegion *DataRegionList::findRegionContaining(address_t target) {
    // check for TLS region first, since it will overlap another LOAD segment
    if(tls && tls->containsData(target)) return tls;

    return findNonTLSRegionContaining(target);
}

DataRegion *DataRegionList::findNonTLSRegionContaining(address_t target) {
    //auto found = getChildren()->getSpatial()->findContaining(target);
    //if(found && found != tls) return found;

    // FIX: this is very slow as a linear search for jump tables
    for(auto region : CIter::children(this)) {
        if(region == tls) continue;

        if(region->contains(target)) {
            return region;
        }
    }
    return nullptr;
}

DataSection *DataRegionList::findDataSectionContaining(address_t address) {
    auto region = findRegionContaining(address);
    if(region) return region->findDataSectionContaining(address);

    return nullptr;
}

DataSection *DataRegionList::findDataSection(const std::string &name) {
    for(auto region : CIter::children(this)) {
        if(auto section = CIter::named(region)->find(name)) {
            return section;
        }
    }
    return nullptr;
}

DataVariable *DataRegionList::findVariable(const std::string &name) {
    for(auto region : CIter::children(this)) {
        if(auto var = region->findVariable(name)) {
            return var;
        }
    }
    return nullptr;
}

DataVariable *DataRegionList::findVariable(address_t address) {
    auto region = findRegionContaining(address);
    if(region) return region->findVariable(address);

    return nullptr;
}

void DataRegionList::buildDataRegionList(ElfMap *elfMap, Module *module) {
    auto list = new DataRegionList();

    for(void *s : elfMap->getSegmentList()) {
        ElfXX_Phdr *phdr = static_cast<ElfXX_Phdr *>(s);

        if(phdr->p_type == PT_LOAD /*&& phdr->p_flags == (PF_R | PF_W)*/) {
            auto region = new DataRegion(elfMap, phdr);
            LOG(9, "Found data region at 0x"
                << std::hex << region->getAddress()
                << " size 0x" << region->getSize());
            list->getChildren()->add(region);
        }
        else if(phdr->p_type == PT_TLS) {
            auto region = new TLSDataRegion(elfMap, phdr);
            LOG(9, "Found TLS data region at 0x"
                << std::hex << region->getAddress()
                << " size 0x" << region->getSize());
            list->getChildren()->add(region);
            list->setTLS(region);
        }
    }

    for(auto v : elfMap->findSectionsByFlag(SHF_ALLOC)) {
        auto shdr = static_cast<ElfXX_Shdr *>(v);
        DataRegion *region = nullptr;
        if(shdr->sh_flags & SHF_TLS) {
            region = list->getTLS();
        }
        else {
            region = list->findNonTLSRegionContaining(shdr->sh_addr);
        }
        auto ds = new DataSection(elfMap, region->getAddress(), shdr);
        ChunkMutator(region).append(ds);
    }

    module->setDataRegionList(list);
    IF_LOG(10) {
        ChunkDumper dumper;
        for(auto region : CIter::regions(module)) {
            region->accept(&dumper);
        }
    }

    module->setMarkerList(new MarkerList());
}

void DataRegionList::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    writer.writeID(op.assign(tls));
    op.serializeChildren(this, writer);
}

bool DataRegionList::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    tls = op.lookupAs<TLSDataRegion>(reader.readID());
    op.deserializeChildren(this, reader);
    return reader.stillGood();
}
