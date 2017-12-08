#include <cassert>
#include "program.h"
#include "module.h"
#include "library.h"
#include "visitor.h"
#include "serializer.h"
#include "log/log.h"

void Program::add(Module *module) {
    if(getChildren()->getNamed()->find(module->getName())) {
        LOG(1, "WARNING: adding a second module named \""
            << module->getName() << "\" to Program!");
    }

    getChildren()->add(module);

    if(!module->getLibrary() && libraryList) {
        auto libraryName = module->getName().substr(7);
        auto library = libraryList->find(libraryName);
        if(library) {
            library->setModule(module);
            module->setLibrary(library);
        }
    }
}

void Program::add(Library *library) {
    assert(libraryList != nullptr);

    if(!libraryList->add(library)) {
        return;  // duplicate library
    }

    if(!library->getModule()) {
        auto moduleName = "module-" + library->getName();
        if(auto module = getChildren()->getNamed()->find(moduleName)) {
            module->setLibrary(library);
            library->setModule(module);
        }
    }
}

Module *Program::getMain() const {
    if(!libraryList) return nullptr;
    return libraryList->moduleByRole(Library::ROLE_MAIN);
}

Module *Program::getEgalito() const {
    if(!libraryList) return nullptr;
    return libraryList->moduleByRole(Library::ROLE_EGALITO);
}

Module *Program::getLibc() const {
    if(!libraryList) return nullptr;
    return libraryList->moduleByRole(Library::ROLE_LIBC);
}

Module *Program::getLibcpp() const {
    if(!libraryList) return nullptr;
    return libraryList->moduleByRole(Library::ROLE_LIBCPP);
}

address_t Program::getEntryPointAddress() {
    assert(entryPoint != nullptr);
    return entryPoint->getAddress();
}

void Program::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    auto libraryListID = op.serialize(libraryList);
    writer.writeID(libraryListID);
    op.serializeChildren(this, writer);

    LOG(1, "entry point is " << entryPoint);
    writer.write(op.assign(entryPoint));

    LOG(1, "done serializing program");
}

bool Program::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    libraryList = op.lookupAs<LibraryList>(reader.readID());
    op.deserializeChildren(this, reader);

    entryPoint = op.lookup(reader.readID());
    return reader.stillGood();
}

void Program::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
