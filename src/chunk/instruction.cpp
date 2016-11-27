#include <cstring>
#include "instruction.h"

void SemanticImpl::setSize(size_t value) {
    throw "Can't set size for this instruction type!";
}

std::string SemanticImpl::getData() {
    std::string data;
    writeTo(data);
    return data;
}

void UnprocessedInstruction::writeTo(char *target) {
    std::memcpy(target, rawData.c_str(), rawData.size());
}
void UnprocessedInstruction::writeTo(std::string &target) {
    target.append(rawData);
}

void NormalSemanticImpl::writeTo(char *target) {
    std::memcpy(target, insn.bytes, insn.size);
}
void NormalSemanticImpl::writeTo(std::string &target) {
    target.append(reinterpret_cast<char *>(insn.bytes), insn.size);
}
