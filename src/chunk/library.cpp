#include "library.h"
#include "module.h"
#include "serializer.h"
#include "visitor.h"
#include "log/log.h"

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

Library::Role Library::guessRole(const std::string &name) {
    if(name.find("libc.so") != std::string::npos) return ROLE_LIBC;
    if(name.find("libstdc++.so") != std::string::npos) return ROLE_LIBCPP;
    if(name.find("libegalito.so") != std::string::npos) return ROLE_EGALITO;

    return ROLE_NORMAL;
}

bool LibraryList::add(Library *library) {
    if(auto other = find(library->getName())) {
        if(library->getRole() != other->getRole()) {
            LOG(1, "WARNING: trying to add library \"" << library->getName()
                << "\" a second time with different Role, skipping");
        }

        // already have this library, don't add it
        delete library;
        return false;
    }

    getChildren()->add(library);
    saveRole(library);

    return true;
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
