#include "semantic.h"
#include "assembly.h"

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

std::string DisassembledStorage::getData() const {
    return std::move(assembly.getBytes());
}
