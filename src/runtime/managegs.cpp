#ifndef _GNU_SOURCE
    #define _GNU_SOURCE
#endif
#include <iomanip>

#ifdef ARCH_X86_64
    #include <asm/prctl.h>
#endif
#include <sys/prctl.h>
#include <sys/mman.h>
#include <cassert>

#include "managegs.h"
#include "chunk/concrete.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP load
#include "log/log.h"

// must fit in the 32bits; see usegstable.cpp
#define FUNCTION_TABLE_SIZE 64 * 0x1000

extern "C" int arch_prctl(int code, unsigned long addr);

void ManageGS::init(GSTable *gsTable) {
#ifdef ARCH_X86_64
    auto count = gsTable->getChildren()->getIterable()->getCount();
    assert(count < FUNCTION_TABLE_SIZE/sizeof(address_t));

    void *buffer = mmap(NULL, FUNCTION_TABLE_SIZE, PROT_READ|PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    LOG(1, "Initializing GS table at " << std::hex << buffer);

    gsTable->setTableAddress(buffer);

    address_t *array = static_cast<address_t *>(buffer);
    for(auto entry : CIter::children(gsTable)) {
        LOG(1, "    gs@[" << std::dec << entry->getIndex() << "] -> "
            << std::hex << entry->getTarget()->getAddress()
            << " = " << entry->getTarget()->getName()
            << " -> "
            << std::hex << entry->getRealTarget()->getAddress()
            << " = " << entry->getRealTarget()->getName());
        array[entry->getIndex()] = entry->getTarget()->getAddress();
    }

    arch_prctl(ARCH_SET_GS, reinterpret_cast<unsigned long>(buffer));
#endif
}

void ManageGS::setEntry(GSTable *gsTable, GSTableEntry::IndexType index,
    address_t value) {

    assert(index < FUNCTION_TABLE_SIZE/sizeof(address_t));
    address_t *array = static_cast<address_t *>(gsTable->getTableAddress());
    array[index] = value;
}

void ManageGS::resetEntries(GSTable *gsTable, Chunk *callback) {
    address_t *array = static_cast<address_t *>(gsTable->getTableAddress());
    for(auto entry : CIter::children(gsTable)) {
        LOG(12, "set resolver for " << entry->getTarget()->getName());
        entry->setLazyResolver(callback);
        // don't use callback's address; some have to be pre-resolved
        array[entry->getIndex()] = entry->getTarget()->getAddress();
    }
}

Chunk *ManageGS::resolve(GSTable *gsTable, GSTableEntry::IndexType index) {
    auto entry = gsTable->getAtIndex(index);
    entry->setLazyResolver(nullptr);
    ManageGS::setEntry(gsTable, index, entry->getTarget()->getAddress());
    return entry->getTarget();
}
