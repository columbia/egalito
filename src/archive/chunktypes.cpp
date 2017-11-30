#include "chunktypes.h"

uint8_t encodeChunkType(EgalitoChunkType type) {
    static uint8_t encode[] = {
        '?',    // TYPE_UNKNOWN
        'P',    // TYPE_Program
        'M',    // TYPE_Module
        'F',    // TYPE_FunctionList
        'L',    // TYPE_PLTList
        'T',    // TYPE_JumpTableList
        'R',    // TYPE_DataRegionList
        'f',    // TYPE_Function
        'b',    // TYPE_Block
        'i',    // TYPE_Instruction
        'l',    // TYPE_PLTTrampoline
        'J',    // TYPE_JumpTable
        'j',    // TYPE_JumpTableEntry
        'D',    // TYPE_DataRegion
        'd',    // TYPE_DataSection
        'v',    // TYPE_DataVariable
        'A',    // TYPE_MarkerList
        'a',    // TYPE_Marker
    };
    return encode[type];
}

EgalitoChunkType decodeChunkType(uint8_t encoded) {
    switch(encoded) {
    case '?': return TYPE_UNKNOWN;
    case 'P': return TYPE_Program;
    case 'M': return TYPE_Module;
    case 'F': return TYPE_FunctionList;
    case 'L': return TYPE_PLTList;
    case 'T': return TYPE_JumpTableList;
    case 'R': return TYPE_DataRegionList;
    case 'f': return TYPE_Function;
    case 'b': return TYPE_Block;
    case 'i': return TYPE_Instruction;
    case 'l': return TYPE_PLTTrampoline;
    case 'J': return TYPE_JumpTable;
    case 'j': return TYPE_JumpTableEntry;
    case 'D': return TYPE_DataRegion;
    case 'd': return TYPE_DataSection;
    case 'v': return TYPE_DataVariable;
    case 'A': return TYPE_MarkerList;
    case 'a': return TYPE_Marker;
    }
    return TYPE_UNKNOWN;
}
