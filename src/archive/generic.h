#ifndef EGALITO_ARCHIVE_GENERIC_H
#define EGALITO_ARCHIVE_GENERIC_H

#include <cstdint>

namespace EgalitoArchive {

extern const char *signature;
static const uint32_t version = 0;

enum EgalitoChunkType {
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

}  // namespace EgalitoArchive

#endif
