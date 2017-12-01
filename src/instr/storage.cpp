#include "semantic.h"
#include "instr.h"
#include "disasm/handle.h"
#include "disasm/disassemble.h"

InstructionStorage::AssemblyPtr InstructionStorage::getAssembly(
    address_t address) {

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
}

AssemblyFactory AssemblyFactory::instance;

AssemblyFactory::AssemblyPtr AssemblyFactory::buildAssembly(
    InstructionStorage *storage, address_t address) {

    static DisasmHandle handle(true);
    auto assembly = DisassembleInstruction(handle, true)
        .allocateAssembly(storage->getData(), address);
    auto ptr = std::make_shared(assembly);
    assemblyList.push_back(ptr);
    return ptr;
}

void AssemblyFactory::registerAssembly(AssemblyPtr assembly) {
    assemblyList.push_back(assembly);
}

void AssemblyFactory::clearCache() {
    assemblyList.clear();
}
