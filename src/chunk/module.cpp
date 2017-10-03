#include <string>
#include <sstream>
#include "module.h"
#include "elf/elfspace.h"
#include "elf/sharedlib.h"
#include "serializer.h"
#include "visitor.h"
#include "log/log.h"

std::string Module::getName() const {
    std::ostringstream stream;
    if(!elfSpace) return "module-???";
    auto lib = elfSpace->getLibrary();
    if(lib) {
        stream << "module-" << lib->getShortName();
    }
    else {
        stream << "module-main";
    }
    return stream.str();
}

void Module::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    writer.writeAnyLength(getName());

    auto functionList = op.serialize(getFunctionList());
    LOG(1, "about to write functionList id...");
    writer.write(functionList);
    LOG(1, "done with functionList id");
}

bool Module::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    std::string name;
    reader.readAnyLength(name);

    LOG(1, "trying to parse Module [" << name << "]");

    uint32_t id;
    reader.read(id);
    auto functionList = op.lookupAs<FunctionList>(id);
    getChildren()->add(functionList);
    setFunctionList(functionList);

    return reader.stillGood();
}

void Module::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
