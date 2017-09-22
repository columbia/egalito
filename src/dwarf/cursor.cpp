#include <climits>
#include "cursor.h"
#include "log/log.h"

int64_t DwarfCursor::nextSleb128() {
    int64_t result = 0;
    uint32_t shift = 0;
    uint8_t byte;
    do {
        byte = next<uint8_t>();
        result |= (byte & 0x7f) << shift;
        shift += 7;
    } while(byte & 0x80);

    if((byte & 0x40) && shift < 128) {
        result |= LONG_LONG_MAX << shift;
    }

    return result;
}

uint64_t DwarfCursor::nextUleb128() {
    uint64_t result = 0;
    uint32_t shift = 0;
    uint8_t byte;
    do {
        byte = next<uint8_t>();
        result |= (byte & 0x7f) << shift;
        shift += 7;
    } while(byte & 0x80);

    return result;
}

uint8_t *DwarfCursor::nextString() {
    uint8_t *str = reinterpret_cast<uint8_t *>(cursor);
    while(next<uint8_t>()) {}
    return str;
}

int64_t DwarfCursor::parseNextEncodedPointer(uint8_t encoding) {
    int64_t result = 0;

    if(encoding == DW_EH_PE_omit) return 0;

    switch(encoding & 0x70) {
    case DW_EH_PE_absptr:
        // just add the value in the next switch statement
        break;
    case DW_EH_PE_pcrel:
        result = cursor;  // value below is relative to the current cursor
        break;
    default:
        LOG(0, "WARNING: unknown pointer encoding " << encoding);
    }

    switch(encoding & 0x0f) {
    case DW_EH_PE_ptr:      result += next<uint64_t>(); break;
    case DW_EH_PE_udata8:   result += next<uint64_t>(); break;
    case DW_EH_PE_uleb128:  result += nextUleb128(); break;
    case DW_EH_PE_udata2:   result += next<uint16_t>(); break;
    case DW_EH_PE_udata4:   result += next<uint32_t>(); break;
    case DW_EH_PE_sleb128:  result += nextSleb128(); break;
    case DW_EH_PE_sdata2:   result += next<int16_t>(); break;
    case DW_EH_PE_sdata4:   result += next<int32_t>(); break;
    case DW_EH_PE_sdata8:   result += next<int64_t>(); break;
    default:
        LOG(0, "WARNING: unknown pointer encoding " << encoding);
    }

    return result;
}
