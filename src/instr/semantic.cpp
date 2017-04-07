#include <cstring>  // for memcpy
#include "semantic.h"
#include "assembly.h"

void RawByteStorage::writeTo(char *target) {
    std::memcpy(target, rawData.c_str(), rawData.size());
}
void RawByteStorage::writeTo(std::string &target) {
    target.append(rawData);
}
std::string RawByteStorage::getData() {
    return rawData;
}

DisassembledStorage::DisassembledStorage(DisassembledStorage &&other) {
    this->assembly = other.assembly;
}

DisassembledStorage::~DisassembledStorage() {
}

DisassembledStorage &DisassembledStorage::operator = (
    DisassembledStorage &&other) {

    this->assembly = other.assembly;
    return *this;
}

void DisassembledStorage::writeTo(char *target) {
    std::memcpy(target, assembly.getBytes(), assembly.getSize());
}
void DisassembledStorage::writeTo(std::string &target) {
    target.append(assembly.getBytes(), assembly.getSize());
}
std::string DisassembledStorage::getData() {
    std::string data;
    data.assign(assembly.getBytes(), assembly.getSize());
    return std::move(data);
}
