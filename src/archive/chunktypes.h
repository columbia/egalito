#ifndef EGALITO_ARCHIVE_CHUNK_TYPES_H
#define EGALITO_ARCHIVE_CHUNK_TYPES_H

#include <cstdint>

enum EgalitoChunkType {
    TYPE_UNKNOWN = 0,
    TYPE_Program,
    TYPE_Module,
    TYPE_FunctionList,
    TYPE_PLTList,
    TYPE_JumpTableList,
    TYPE_DataRegionList,
    TYPE_ExternalSymbolList,
    TYPE_LibraryList,
    TYPE_Function,
    TYPE_Block,
    TYPE_Instruction,
    TYPE_PLTTrampoline,
    TYPE_JumpTable,
    TYPE_JumpTableEntry,
    TYPE_DataRegion,
    TYPE_TLSDataRegion,
    TYPE_DataSection,
    TYPE_DataVariable,
    TYPE_MarkerList,
    TYPE_Marker,
    TYPE_ExternalSymbol,
    TYPE_Library,
};

uint8_t encodeChunkType(EgalitoChunkType type);
EgalitoChunkType decodeChunkType(uint8_t encoded);

#endif
