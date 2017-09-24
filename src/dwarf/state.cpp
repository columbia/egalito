#include "state.h"

DwarfState::DwarfState() : next(nullptr), cfaRegister(0), cfaOffset(0),
    cfaExpression(0), cfaExpressionLength(0) {

}

DwarfState::DwarfState(const DwarfState &other)
    : registers(other.registers), next(other.next),
    cfaRegister(other.cfaRegister), cfaOffset(other.cfaOffset),
    cfaExpression(other.cfaExpression),
    cfaExpressionLength(other.cfaExpressionLength) {

}
