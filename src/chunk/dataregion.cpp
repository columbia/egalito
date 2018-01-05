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
#include "chunk/dump.h"
#include "elf/elfspace.h"
#include "operation/find.h"
#include "operation/mutator.h"
#include "util/streamasstring.h"
#include "log/log.h"
#include "log/temp.h"

DataVariable::DataVariable(DataRegion *region, address_t address, Link *dest)
    : dest(dest) {

    auto section = CIter::spatial(region)->findContaining(address);
    if(!section) {
        LOG(10, "in " << region->getName() << ", address " << address);
        ChunkDumper dumper;
        region->accept(&dumper);
        throw "no section contains this variable!";
    }

    auto offset = address - section->getAddress();
    this->setPosition(new AbsoluteOffsetPosition(this, offset));
    region->setParent(nullptr);
    ChunkMutator(section).append(this);
}

DataVariable::DataVariable(DataSection *section, address_t address, Link *dest)
    : dest(dest) {

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
        
    }
    else {
        LinkSerializer(op).serialize(dest, writer);
    }
}

bool DataVariable::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    setParent(op.lookup(reader.readID()));
    setPosition(new AbsoluteOffsetPosition(this, reader.read<address_t>()));
    name = reader.readString();
    dest = LinkSerializer(op).deserialize(reader);
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
    if(shdr->sh_flags & SHF_EXECINSTR) type = TYPE_CODE;
    else if(shdr->sh_type == SHT_NOBITS) type = TYPE_BSS;
    else if(shdr->sh_type == SHT_INIT_ARRAY) type = TYPE_INIT_ARRAY;
    else if(shdr->sh_type == SHT_FINI_ARRAY) type = TYPE_FINI_ARRAY;
    else type = TYPE_UNKNOWN;
}

std::string DataSection::getName() const {
    return name;
}

bool DataSection::contains(address_t address) {
    return getRange().contains(address);
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

void DataRegion::saveDataBytes() {
    const char *address = reinterpret_cast<const char *>(getAddress());
    size_t size = dataBytes.size();
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

void DataRegion::addVariable(DataVariable *variable) {
    variableList.push_back(variable);
}

DataVariable *DataRegion::findVariable(const std::string &name) {
    // !!! linear search for now
    for(auto var : variableList) {
        if(var->getName() == name) {
            return var;
        }
    }
    return nullptr;
}

DataVariable *DataRegion::findVariable(address_t address) const {
    for(auto var : variableList) {
        if(var->getAddress() == address) {
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

void DataRegion::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    writer.write(getAddress());
    writer.write(getSize());
    writer.write(originalAddress);
    writer.write(permissions);
    writer.write(alignment);
    writer.writeBytes<uint64_t>(dataBytes);

    writer.write<uint64_t>(variableList.size());
    for(auto var : variableList) {
        writer.writeID(op.serialize(var));
    }

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

    uint64_t varCount = reader.read<uint64_t>();
    for(uint64_t i = 0; i < varCount; i ++) {
        variableList.push_back(op.lookupAs<DataVariable>(reader.readID()));
    }

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
    auto size = getSizeOfInitializedData();
    return Range(getAddress(), size).contains(address);
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

    LOG(10, "MAKE LINK to " << std::hex << target
        << ", relative? " << isRelative);

    for(auto region : CIter::children(this)) {
        if(region->contains(target)) {
            auto dsec = CIter::spatial(region)->findContaining(target);
            if(dsec) {
                if(dsec->getType() == DataSection::TYPE_CODE) {
                    if(ChunkFind().findInnermostAt(
                        module->getFunctionList(), target)) {

                        LOG(1, "is this a hand-crafted jump table? " << target);
                        return nullptr;
                    }
                    else {
                        // this will very likely to result in a too-far
                        // link for AARCH64.
                        LOG(9, "is this a LITERAL? " << target);
                        return nullptr;
                    }
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
