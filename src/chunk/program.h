#ifndef EGALITO_CHUNK_PROGRAM_H
#define EGALITO_CHUNK_PROGRAM_H

#include "chunk.h"
#include "chunklist.h"
#include "archive/chunktypes.h"

class Module;
class Library;
class LibraryList;

/** Root class for the entire Chunk heirarchy. The children of this class are
    Modules, which are parsed from individual ELF files. The Program also
    stores a LibraryList (not in the child list) which indicates the Modules
    that are needed to resolve all references but which may not be loaded.
*/
class Program : public ChunkSerializerImpl<TYPE_Program,
    CollectionChunkImpl<Module>> {
private:
    LibraryList *libraryList;
    Chunk *entryPoint;
public:
    Program() : libraryList(nullptr), entryPoint(nullptr) {}

    void add(Module *module);
    void add(Library *library);

    Module *getMain() const;
    Module *getEgalito() const;
    Module *getLibc() const;
    Module *getLibcpp() const;

    LibraryList *getLibraryList() const { return libraryList; }
    void setLibraryList(LibraryList *list) { libraryList = list; }

    void setEntryPoint(Chunk *chunk) { entryPoint = chunk; }
    Chunk *getEntryPoint() const { return entryPoint; }
    address_t getEntryPointAddress();

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    virtual void accept(ChunkVisitor *visitor);
};

#endif
