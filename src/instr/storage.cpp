#include "semantic.h"
#include "instr.h"
#include "disasm/handle.h"
#include "disasm/disassemble.h"

const std::string &InstructionStorage::getData() const {
    return rawData;
}

size_t InstructionStorage::getSize() const {
    return rawData.size();
}

AssemblyPtr InstructionStorage::getAssembly(address_t address) {
    AssemblyPtr ptr = assembly.lock();
    if(!ptr) {
        ptr = AssemblyFactory::getInstance()->buildAssembly(this, address);
        this->assembly = ptr;
    }
    return ptr;
}

void InstructionStorage::setAssembly(AssemblyPtr assembly) {
    AssemblyFactory::getInstance()->registerAssembly(assembly);
    this->assembly = assembly;

    if(rawData.empty()) {
        rawData.assign(assembly->getBytes(), assembly->getSize());
    }
}

AssemblyFactory AssemblyFactory::instance;

AssemblyPtr AssemblyFactory::buildAssembly(InstructionStorage *storage,
    address_t address) {

    static DisasmHandle handle(true);
    auto assembly = DisassembleInstruction(handle, true)
        .allocateAssembly(storage->getData(), address);
    auto ptr = AssemblyPtr(assembly);
    assemblyList.push_back(ptr);
    return ptr;
}

void AssemblyFactory::registerAssembly(AssemblyPtr assembly) {
    assemblyList.push_back(assembly);
}

void AssemblyFactory::clearCache() {
    assemblyList.clear();
}
