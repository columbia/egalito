#ifndef EGALITO_CHUNK_LIBRARY_H
#define EGALITO_CHUNK_LIBRARY_H

#include <string>
#include <vector>
#include <set>
#include "chunk.h"

class ElfSpace;

/** Represents a shared library dependency, or rather a Module which may or
    may not be present. If only one Module is present because a single ELF file
    is being parsed, for instance, it may depend on many other ELF files, which
    will all appear in the Library list.
*/
class Library : public ChunkSerializerImpl<TYPE_Library, ChunkImpl> {
public:
    enum Role {
        ROLE_UNKNOWN,
        ROLE_EXECUTABLE,    // target executable
        ROLE_EGALITO,       // injected libegalito
        ROLE_LIBC,
        ROLE_LIBCPP,
        ROLE_NORMAL,        // any other library -- may be multiple
        ROLE_SUPPORT,       // any tool support lib -- may be multiple
        ROLES
    };
private:
    std::string name;
    Role role;
    Module *module;
    ElfSpace *elfSpace;
    std::string resolvedPath;
public:
    Library() : module(nullptr), elfSpace(nullptr) {}
    Library(const std::string &name, Role role) : name(name), role(role),
        module(nullptr), elfSpace(nullptr) {}

    const std::string &getName() const { return name; }
    void setName(const std::string &name) { this->name = name; }

    /** Returns the module corresponding to this library, or NULL if it has
        not been loaded.
    */
    Module *getModule() const { return module; }
    void setModule(Module *module) { this->module = module; }

    Role getRole() const { return role; }
    ElfSpace *getElfSpace() const { return elfSpace; }
    void setRole(Role role) { this->role = role; }
    void setElfSpace(ElfSpace *elfSpace) { this->elfSpace = elfSpace; }

    const std::string &getResolvedPath() const { return resolvedPath; }
    void setResolvedPath(const std::string &path) { resolvedPath = path; }
};

class LibraryList : public ChunkSerializerImpl<TYPE_LibraryList,
    CompositeChunkImpl<Library>> {
private:
    std::vector<std::string> searchPaths;
    std::set<std::string> searchPathSet;
    Library roleMap[Library::ROLES];
public:
    void saveRole(Library *library);
    Library *byRole(Library::Role role);

    Library *getExecutable() const { return roleMap[Library::ROLE_EXECUTABLE]; }
    Library *getEgalito() const { return roleMap[Library::ROLE_EGALITO]; }
    Library *getLibc() const { return roleMap[Library::ROLE_LIBC]; }
    Library *getLibcpp() const { return roleMap[Library::ROLE_LIBCPP]; }
};

#endif
