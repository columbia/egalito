#include <string>
#include <sstream>
#include "module.h"
#include "elf/elfspace.h"
#include "elf/sharedlib.h"
#include "serializer.h"
#include "visitor.h"
#include "log/log.h"

void Module::setElfSpace(ElfSpace *space) {
    elfSpace = space;

    // set name based on ElfSpace
    std::ostringstream stream;
    auto lib = elfSpace->getLibrary();
    if(lib) {
        stream << "module-" << lib->getShortName();
    }
    else {
        stream << "module-main";
    }
    setName(stream.str());
}

void Module::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    writer.writeString(getName());

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
