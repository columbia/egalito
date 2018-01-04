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

#include "config.h"
#include "managegs.h"
#include "chunk/concrete.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP load
#include "log/log.h"

extern "C" int arch_prctl(int code, unsigned long addr);

void ManageGS::init(GSTable *gsTable) {
#ifdef ARCH_X86_64
    auto count = gsTable->getChildren()->getIterable()->getCount();
    assert(count < JIT_TABLE_SIZE/sizeof(address_t));

    void *buffer = mmap(NULL, JIT_TABLE_SIZE, PROT_READ|PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    LOG(1, "Initializing GS table at " << std::hex << buffer);

    gsTable->setTableAddress(buffer);

    address_t *array = static_cast<address_t *>(buffer);
    for(auto entry : CIter::children(gsTable)) {
        LOG0(1, "    gs@[" << std::dec << entry->getIndex() << "] -> "
            << entry->getTarget()->getName()
            << " -> "
            << std::hex << entry->getRealTarget()->getAddress()
            << " = " << entry->getRealTarget()->getName());
        bool b = false;
        if(auto p = entry->getRealTarget()->getParent()) {
            if(auto pp = p->getParent()) {
                LOG(1, " in " << pp->getName());
                b = true;
            }
        }
        if(!b) {
            LOG(1, "");
        }

        array[entry->getIndex()] = entry->getTarget()->getAddress();
    }

    arch_prctl(ARCH_SET_GS, reinterpret_cast<unsigned long>(buffer));
#endif
}

void ManageGS::allocateBuffer(GSTable *gsTable) {
    void *buffer = mmap(NULL, JIT_TABLE_SIZE, PROT_READ|PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    gsTable->setTableAddress(buffer);
}

void ManageGS::setGS(GSTable *gsTable) {
#ifdef ARCH_X86_64
    auto buffer = gsTable->getTableAddress();
    arch_prctl(ARCH_SET_GS, reinterpret_cast<unsigned long>(buffer));
#endif
}

void ManageGS::setEntry(GSTable *gsTable, GSTableEntry::IndexType index,
    address_t value) {

    assert(index < JIT_TABLE_SIZE/sizeof(address_t));
    address_t *array = static_cast<address_t *>(gsTable->getTableAddress());
    array[index] = value;
}

address_t ManageGS::getEntry(GSTableEntry::IndexType offset) {
    address_t address = 0;
#ifdef ARCH_X86_64
    __asm__ __volatile__ (
        "mov %%gs:(%1), %0"
            : "=r"(address)
            : "r"(offset)
    );
#endif
    return address;
}

void ManageGS::resetEntries(GSTable *gsTable, Chunk *callback) {
    address_t *array = static_cast<address_t *>(gsTable->getTableAddress());
    for(auto entry : CIter::children(gsTable)) {
        //if(dynamic_cast<GSTableResolvedEntry *>(entry)) continue;

        LOG(12, "set resolver for " << entry->getTarget()->getName());
        entry->setLazyResolver(callback);
        //array[entry->getIndex()] = callback->getAddress();
        array[entry->getIndex()] = entry->getTarget()->getAddress();
    }
}

Chunk *ManageGS::resolve(GSTable *gsTable, GSTableEntry::IndexType index) {
    auto entry = gsTable->getAtIndex(index);
    entry->setLazyResolver(nullptr);
    ManageGS::setEntry(gsTable, index, entry->getTarget()->getAddress());
    return entry->getTarget();
}
