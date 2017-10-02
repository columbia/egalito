#ifndef EGALITO_ARCHIVE_ARCHIVE_H
#define EGALITO_ARCHIVE_ARCHIVE_H

#include <cstdint>
#include "flatchunk.h"

class EgalitoArchive {
public:
    static const char *signature;
    static const uint32_t version = 1;

    enum EgalitoChunkType {
        TYPE_UNKNOWN = 0,
        TYPE_Program,
        TYPE_Module,
        TYPE_FunctionList,
        TYPE_PLTList,
        TYPE_JumpTableList,
        TYPE_DataRegionList,
        TYPE_Function,
        TYPE_Block,
        TYPE_Instruction,
        TYPE_PLTTrampoline,
        TYPE_JumpTable,
        TYPE_JumpTableEntry,
        TYPE_DataRegion,
        TYPE_DataSection,
        TYPE_DataVariable,
        TYPE_MarkerList,
        TYPE_Marker,
    };
private:
    FlatChunkList flatList;
    std::string sourceFilename;
public:
    EgalitoArchive() : sourceFilename("(in-memory)") {}
    EgalitoArchive(std::string filename) : sourceFilename(filename) {}

    FlatChunkList &getFlatList() { return flatList; }
};

#endif
