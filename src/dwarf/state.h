#ifndef EGALITO_DWARF_STATE_H
#define EGALITO_DWARF_STATE_H

#include "types.h"

class DwarfRegisterData {
private:
    int32_t type;
    uint64_t offset;
public:
    DwarfRegisterData() : type(0), offset(0) {}
    DwarfRegisterData(int32_t type, uint64_t offset)
        : type(type), offset(offset) {}
    int32_t getType() const { return type; }
    uint64_t getOffset() const { return offset; }
};

class DwarfState {
private:
    static const int NUM_REGISTERS = 17;
private:
    DwarfRegisterData registers[NUM_REGISTERS];
    DwarfState *next;
    uint64_t cfaRegister;
    int64_t cfaOffset;
    address_t cfaExpression;
    size_t cfaExpressionLength;
public:
    DwarfState();
    DwarfState(const DwarfState &other);

    DwarfRegisterData &get(uint64_t reg) { return registers[reg]; }
    void set(uint64_t reg, const DwarfRegisterData &data)
        { registers[reg] = data; }
    void set(uint64_t reg, int32_t type, uint64_t offset)
        { registers[reg] = DwarfRegisterData(type, offset); }

    void setNext(DwarfState *next) { this->next = next; }
    void setCfaRegister(uint64_t cfaRegister)
        { this->cfaRegister = cfaRegister; }
    void setCfaOffset(int64_t cfaOffset) { this->cfaOffset = cfaOffset; }
    void setCfaExpression(address_t cfaExpression)
        { this->cfaExpression = cfaExpression; }
    void setCfaExpressionLength(size_t len) { cfaExpressionLength = len; }

    DwarfState *getNext() const { return next; }
    uint64_t getCfaRegister() const { return cfaRegister; }
    int64_t getCfaOffset() const { return cfaOffset; }
    address_t getCfaExpression() const { return cfaExpression; }
};

#endif
