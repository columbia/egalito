#ifndef _GNU_SOURCE
    #define _GNU_SOURCE
#endif
#include <iomanip>

#ifdef ARCH_X86_64
    #include <asm/prctl.h>
#endif
#include <sys/prctl.h>
#include <sys/mman.h>
#include <cstring>
#include <cassert>

#include "config.h"
#include "managegs.h"
#include "chunk/concrete.h"
#include "chunk/tls.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP load
#include "log/log.h"

extern "C" int arch_prctl(int code, unsigned long addr);

extern Chunk *egalito_gsCallback;

void ManageGS::init(GSTable *gsTable) {
#ifdef ARCH_X86_64
    assert(egalito_gsCallback);

    auto count = gsTable->getChildren()->getIterable()->getCount();
    assert(count < JIT_TABLE_SIZE/sizeof(address_t));

    void *buffer = mmap(NULL, JIT_TABLE_SIZE, PROT_READ|PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    LOG(1, "Initializing GS table at " << std::hex << buffer);
    LOG(1, "callback address is "
        << std::hex << egalito_gsCallback->getAddress());

    gsTable->setTableAddress(buffer);

    auto jitStart = gsTable->getJITStartIndex();
    auto jitEnd = gsTable->getChildren()->getIterable()->getCount();
    address_t *array = static_cast<address_t *>(gsTable->getTableAddress());
    LOG(1, "will set the address egalito_gsCallback"
        << " from " << std::hex << &array[jitStart]
        << " to " << &array[jitEnd]);
    ManageGS::resetEntries(gsTable, egalito_gsCallback);
    //if(1) { // to debug RELEASE_BUILD
    IF_LOG(1) {
        for(auto entry : CIter::children(gsTable)) {
            if(entry->getIndex() == gsTable->getJITStartIndex()) {
                std::cout << "---- JIT entries ----" << '\n';
            }
            std::cout << "    gs@[" << std::dec << entry->getIndex() << "] -> "
                << entry->getTarget()->getName() << " at "
                << std::hex << entry->getTarget()->getAddress();

            if(auto p = entry->getTarget()->getParent()) {
                if(auto pp = p->getParent()) {
                    std::cout << " in " << pp->getName();
                }
            }
            std::cout << '\n';
        }
        std::cout.flush();
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

extern bool egalito_init_done;
void ManageGS::resetEntries(GSTable *gsTable, Chunk *callback) {
    address_t *array = static_cast<address_t *>(gsTable->getTableAddress());
    auto jitStart = gsTable->getJITStartIndex();
    auto jitEnd = gsTable->getChildren()->getIterable()->getCount();

    if(egalito_init_done) {
        auto table = EgalitoTLS::getJITAddressTable();
        std::memcpy(&array[0], table, jitStart*sizeof(address_t));
        for(auto entry : CIter::children(gsTable)) {
            auto i = entry->getIndex();
            if(i == jitStart) break;

            if(array[i] == 0) { // target does not have an absolute position
                array[i] = entry->getTarget()->getAddress();
            }
        }
    }
    else {
        for(auto entry : CIter::children(gsTable)) {
            auto i = entry->getIndex();
            if(i == jitStart) break;

            array[i] = entry->getTarget()->getAddress();
        }
    }

    // should be < 10us without vector instructions
    auto addr = callback->getAddress();
    for(size_t i = jitStart; i < jitEnd; i++) {
        array[i] = addr;
    }
}

Chunk *ManageGS::resolve(GSTable *gsTable, GSTableEntry::IndexType index) {
    auto entry = gsTable->getAtIndex(index);
    ManageGS::setEntry(gsTable, index, entry->getTarget()->getAddress());
    return entry->getTarget();
}
