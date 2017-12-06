#include <string>
#include "module.h"
#include "library.h"
#include "elf/elfspace.h"
#include "elf/sharedlib.h"
#include "serializer.h"
#include "visitor.h"
#include "util/streamasstring.h"
#include "log/log.h"

void Module::setElfSpace(ElfSpace *elfSpace) {
    this->elfSpace = elfSpace;

    // set name based on ElfSpace
    setName(StreamAsString() << "module-" << elfSpace->getName());
}

void Module::setLibrary(Library *library) {
    this->library = library;

    // set name based on Library
    setName(StreamAsString() << "module-" << library->getName());
}

void Module::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    writer.writeString(getName());
    writer.writeID(op.assign(library));

    auto pltListID = op.serialize(getPLTList());
    writer.write(pltListID);

    auto functionListID = op.serialize(getFunctionList());
    writer.write(functionListID);

    auto jumpTableListID = op.serialize(getJumpTableList());
    writer.write(jumpTableListID);

    auto dataRegionListID = op.serialize(getDataRegionList());
    writer.write(dataRegionListID);
}

bool Module::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    setName(reader.readString());
    library = op.lookupAs<Library>(reader.readID());

    LOG(1, "trying to parse Module [" << name << "]");

    {
        auto id = reader.readID();
        auto pltList = op.lookupAs<PLTList>(id);
        getChildren()->add(pltList);
        setPLTList(pltList);
    }

    {
        auto id = reader.readID();
        auto functionList = op.lookupAs<FunctionList>(id);
        getChildren()->add(functionList);
        setFunctionList(functionList);
    }

    {
        auto id = reader.readID();
        auto jumpTableList = op.lookupAs<JumpTableList>(id);
        if(jumpTableList) {
            getChildren()->add(jumpTableList);
            setJumpTableList(jumpTableList);
        }
    }

    {
        auto id = reader.readID();
        auto dataRegionList = op.lookupAs<DataRegionList>(id);
        if(dataRegionList) {
            getChildren()->add(dataRegionList);
            setDataRegionList(dataRegionList);
        }
    }

    return reader.stillGood();
}

void Module::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
