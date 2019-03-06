#ifndef EGALITO_CHUNK_LIBRARY_H
#define EGALITO_CHUNK_LIBRARY_H

#include <string>
#include <vector>
#include <set>
#include "chunk.h"
#include "chunklist.h"
#include "archive/chunktypes.h"

class Module;

/** Represents a shared library dependency, or rather a Module which may or
    may not be present. If only one Module is present because a single ELF file
    is being parsed, for instance, it may depend on many other ELF files, which
    will all appear in the LibraryList.
*/
class Library : public ChunkSerializerImpl<TYPE_Library, ChunkImpl> {
public:
    enum Role {
        ROLE_UNKNOWN,
        ROLE_MAIN,          // target executable
        ROLE_EGALITO,       // injected libegalito
        ROLE_LIBC,
        ROLE_LIBCPP,
        ROLE_NORMAL,        // any other library -- may be multiple
        ROLE_EXTRA,         // extra libraries, not directly referenced
        ROLE_SUPPORT,       // any tool support lib -- may be multiple
        ROLES
    };
private:
    std::string name;
    Role role;
    Module *module;
    std::string resolvedPath;
    std::set<Library *> dependencies;
public:
    Library() : role(ROLE_UNKNOWN), module(nullptr) {}
    Library(const std::string &name, Role role) : name(name), role(role),
        module(nullptr) {}

    std::string getName() const { return name; }
    void setName(const std::string &name) { this->name = name; }

    /** Returns the module corresponding to this library, or NULL if it has
        not been loaded.
    */
    Module *getModule() const { return module; }
    void setModule(Module *module) { this->module = module; }

    Role getRole() const { return role; }
    void setRole(Role role) { this->role = role; }

    const std::string &getResolvedPath() const { return resolvedPath; }
    const char *getResolvedPathCStr() const { return resolvedPath.c_str(); }
    void setResolvedPath(const std::string &path) { resolvedPath = path; }

    const std::set<Library *> getDependencies() { return dependencies; }
    void addDependency(Library *library) { dependencies.insert(library); }

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    virtual void accept(ChunkVisitor *visitor);
public:
    static Role guessRole(const std::string &name);
    static std::string determineInternalName(const std::string &fullPath, Role role);
    static const char *roleAsString(Role role);
};

class LibraryList : public ChunkSerializerImpl<TYPE_LibraryList,
    CompositeChunkImpl<Library>> {
private:
    std::vector<std::string> searchPaths;
    std::set<std::string> searchPathSet;
    Library *roleMap[Library::ROLES];
public:
    bool add(Library *library);

    Library *find(const std::string &name);

    void saveRole(Library *library);
    Library *byRole(Library::Role role);
    Module *moduleByRole(Library::Role role);

    Library *getMain() const { return roleMap[Library::ROLE_MAIN]; }
    Library *getEgalito() const { return roleMap[Library::ROLE_EGALITO]; }
    Library *getLibc() const { return roleMap[Library::ROLE_LIBC]; }
    Library *getLibcpp() const { return roleMap[Library::ROLE_LIBCPP]; }

    void addSearchPath(const std::string &path);
    void addSearchPathToFront(const std::string &path);
    const std::vector<std::string> &getSearchPaths() const
        { return searchPaths; }

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    virtual void accept(ChunkVisitor *visitor);
};

#endif
