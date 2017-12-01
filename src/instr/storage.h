#ifndef EGALITO_INSTR_STORAGE_H
#define EGALITO_INSTR_STORAGE_H

#include <string>
#include <vector>
#include <memory>  // for std::shared_ptr
#include "assembly.h"

class InstructionStorage {
public:
    typedef std::shared_ptr<Assembly> AssemblyPtr;
private:
    std::string rawData;
    std::weak_ptr<Assembly> assembly;
public:
    const std::string &getData() const;
    size_t getSize() const;

    AssemblyPtr getAssembly(address_t address);

    void setData(const std::string &data) { this->rawData = data; }
    void setAssembly(AssemblyPtr assembly);
    void clearAssembly() { assembly.reset(); }
};

class AssemblyFactory {
public:
    typedef InstructionStorage::AssemblyPtr AssemblyPtr;
private:
    static AssemblyFactory instance;
public:
    static AssemblyFactory *getInstance() { return &instance; }
private:
    friend class InstructionStorage;

    std::vector<AssemblyPtr> assemblyList;
public:
    AssemblyPtr buildAssembly(InstructionStorage *storage, address_t address);
    void registerAssembly(AssemblyPtr assembly);
    void clearCache();
};

#endif
