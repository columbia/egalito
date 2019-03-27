#include "chunktypes.h"

uint8_t encodeChunkType(EgalitoChunkType type) {
    static uint8_t encode[] = {
        '?',    // TYPE_UNKNOWN
        'P',    // TYPE_Program
        'M',    // TYPE_Module
        'F',    // TYPE_FunctionList
        'Z',    // TYPE_PLTList
        'T',    // TYPE_JumpTableList
        'R',    // TYPE_DataRegionList
        'S',    // TYPE_ExternalSymbolList
        'L',    // TYPE_LibraryList
        'Q',    // TYPE_VTableList
        'f',    // TYPE_Function
        'b',    // TYPE_Block
        'i',    // TYPE_Instruction
        'z',    // TYPE_PLTTrampoline
        'J',    // TYPE_JumpTable
        'j',    // TYPE_JumpTableEntry
        'D',    // TYPE_DataRegion
        ':',    // TYPE_TLSDataRegion
        'd',    // TYPE_DataSection
        'v',    // TYPE_DataVariable
        'A',    // TYPE_MarkerList
        'a',    // TYPE_Marker
        'V',    // TYPE_VTable
        'p',    // TYPE_VTableEntry
        's',    // TYPE_ExternalSymbol
        'l',    // TYPE_Library
    };
    return encode[type];
}

EgalitoChunkType decodeChunkType(uint8_t encoded) {
    switch(encoded) {
    case '?': return TYPE_UNKNOWN;
    case 'P': return TYPE_Program;
    case 'M': return TYPE_Module;
    case 'F': return TYPE_FunctionList;
    case 'Z': return TYPE_PLTList;
    case 'T': return TYPE_JumpTableList;
    case 'R': return TYPE_DataRegionList;
    case 'S': return TYPE_ExternalSymbolList;
    case 'L': return TYPE_LibraryList;
    case 'Q': return TYPE_VTableList;
    case 'f': return TYPE_Function;
    case 'b': return TYPE_Block;
    case 'i': return TYPE_Instruction;
    case 'z': return TYPE_PLTTrampoline;
    case 'J': return TYPE_JumpTable;
    case 'j': return TYPE_JumpTableEntry;
    case 'D': return TYPE_DataRegion;
    case ':': return TYPE_TLSDataRegion;
    case 'd': return TYPE_DataSection;
    case 'v': return TYPE_DataVariable;
    case 'A': return TYPE_MarkerList;
    case 'a': return TYPE_Marker;
    case 'V': return TYPE_VTable;
    case 'p': return TYPE_VTableEntry;
    case 's': return TYPE_ExternalSymbol;
    case 'l': return TYPE_Library;
    }
    return TYPE_UNKNOWN;
}

const char *getChunkTypeName(EgalitoChunkType type) {
    switch(type) {
    case TYPE_UNKNOWN:            return "UNKNOWN";
    case TYPE_Program:            return "Program";
    case TYPE_Module:             return "Module";
    case TYPE_FunctionList:       return "FunctionList";
    case TYPE_PLTList:            return "PLTList";
    case TYPE_JumpTableList:      return "JumpTableList";
    case TYPE_DataRegionList:     return "DataRegionList";
    case TYPE_InitFunctionList:   return "InitFunctionList";
    case TYPE_ExternalSymbolList: return "ExternalSymbolList";
    case TYPE_LibraryList:        return "LibraryList";
    case TYPE_VTableList:         return "VTableList";
    case TYPE_Function:           return "Function";
    case TYPE_Block:              return "Block";
    case TYPE_Instruction:        return "Instruction";
    case TYPE_PLTTrampoline:      return "PLTTrampoline";
    case TYPE_JumpTable:          return "JumpTable";
    case TYPE_JumpTableEntry:     return "JumpTableEntry";
    case TYPE_DataRegion:         return "DataRegion";
    case TYPE_TLSDataRegion:      return "TLSDataRegion";
    case TYPE_DataSection:        return "DataSection";
    case TYPE_DataVariable:       return "DataVariable";
    case TYPE_GlobalVariable:     return "GlobalVariable";
    case TYPE_MarkerList:         return "MarkerList";
    case TYPE_Marker:             return "Marker";
    case TYPE_VTable:             return "VTable";
    case TYPE_VTableEntry:        return "VTableEntry";
    case TYPE_InitFunction:       return "InitFunction";
    case TYPE_ExternalSymbol:     return "ExternalSymbol";
    case TYPE_Library:            return "Library";
    case TYPE_TOTAL:              return "TOTAL";
    }
    return "???";
}
