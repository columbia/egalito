#ifndef EGALITO_ARCHIVE_OPERATIONS_H
#define EGALITO_ARCHIVE_OPERATIONS_H

#include "archive.h"
#include "flatchunk.h"
#include <map>

/** Generic operations available to serialize/deserialize functions.
*/
template <typename BaseType>
class ArchiveIDOperations {
private:
    EgalitoArchive *archive;
    std::map<BaseType *, FlatChunk::IDType> assignment;
public:
    ArchiveIDOperations(EgalitoArchive *archive) : archive(archive) {}
    virtual ~ArchiveIDOperations() {}
    
    int getVersion() const { return archive->getVersion(); }

    // assign returns NoneID if object is nullptr.
    virtual FlatChunk::IDType assign(BaseType *object);
    bool fetch(BaseType *object, FlatChunk::IDType &id);

    BaseType *lookup(FlatChunk::IDType id) const;
    FlatChunk *lookupFlat(FlatChunk::IDType id) const;

    template <typename Type>
    Type *lookupAs(FlatChunk::IDType id) const {
        if(id == FlatChunk::NoneID) return nullptr;
        return archive->getFlatList().get(id)->getInstance<Type>();
    }
protected:
    EgalitoArchive *getArchive() const { return archive; }
};

template <typename BaseType>
FlatChunk::IDType ArchiveIDOperations<BaseType>::assign(BaseType *object) {
    if(!object) return FlatChunk::NoneID;

    auto it = assignment.find(object);
    if(it != assignment.end()) {
        return (*it).second;
    }

    auto id = archive->getFlatList().getNextID();
    assignment[object] = id;
    return id;
}

template <typename BaseType>
bool ArchiveIDOperations<BaseType>::fetch(BaseType *object,
    FlatChunk::IDType &id) {

    auto it = assignment.find(object);
    if(it != assignment.end()) {
        id = (*it).second;
        return true;
    }

    return false;
}

template <typename BaseType>
BaseType *ArchiveIDOperations<BaseType>::lookup(FlatChunk::IDType id) const {
    if(id == FlatChunk::NoneID) return nullptr;
    return archive->getFlatList().get(id)->getInstance<BaseType>();
}

template <typename BaseType>
FlatChunk *ArchiveIDOperations<BaseType>
    ::lookupFlat(FlatChunk::IDType id) const {

    if(id == FlatChunk::NoneID) return nullptr;
    return archive->getFlatList().get(id);
}

#endif
