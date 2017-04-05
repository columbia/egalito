#include <string>
#include <sstream>
#include <iomanip>
#include "chunk/visitor.h"
#include "instr.h"
#include "semantic.h"

std::string Instruction::getName() const {
    std::ostringstream stream;
    stream << "i/0x" << std::hex << getAddress();
    return stream.str();
}

size_t Instruction::getSize() const {
    return semantic->getSize();
}

void Instruction::setSize(size_t value) {
    semantic->setSize(value);
}

void Instruction::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
