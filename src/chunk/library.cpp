#include "library.h"
#include "module.h"
#include "serializer.h"
#include "visitor.h"

void Library::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    writer.writeString(name);
    writer.write<uint8_t>(role);
    writer.writeID(op.assign(module));
    writer.writeString(resolvedPath);
}

bool Library::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    name = reader.readString();
    role = static_cast<Role>(reader.read<uint8_t>());
    module = op.lookupAs<Module>(reader.readID());
    resolvedPath = reader.readString();

    return reader.stillGood();
}

void Library::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

void LibraryList::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    writer.write<uint16_t>(searchPaths.size());
    for(auto path : searchPaths) {
        writer.writeString(path);
    }

    op.serializeChildren(this, writer);
}

bool LibraryList::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    uint16_t paths = reader.read<uint16_t>();
    for(uint16_t i = 0; i < paths; i ++) {
        searchPaths.push_back(reader.readString());
    }

    op.deserializeChildren(this, reader);
    return reader.stillGood();
}

void LibraryList::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

Library *LibraryList::find(const std::string &name) {
    return getChildren()->getNamed()->find(name);
}

void LibraryList::saveRole(Library *library) {
    if(library->getRole() == Library::ROLE_NORMAL
        || library->getRole() == Library::ROLE_SUPPORT) {
        
        return;
    }

    roleMap[library->getRole()] = library;
}

Library *LibraryList::byRole(Library::Role role) {
    return roleMap[role];
}

Module *LibraryList::moduleByRole(Library::Role role) {
    auto library = roleMap[role];
    return library ? library->getModule() : nullptr;
}
