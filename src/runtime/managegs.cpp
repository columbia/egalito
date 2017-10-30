#ifndef _GNU_SOURCE
    #define _GNU_SOURCE
#endif
#include <iomanip>

#ifdef ARCH_X86_64
    #include <asm/prctl.h>
#endif
#include <sys/prctl.h>
#include <sys/mman.h>

#include "managegs.h"
#include "chunk/concrete.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP load
#include "log/log.h"

#define FUNCTION_TABLE_SIZE 10 * 0x1000

extern "C" int arch_prctl(int code, unsigned long addr);

void ManageGS::init(GSTable *gsTable) {
#ifdef ARCH_X86_64
    void *buffer = mmap(NULL, FUNCTION_TABLE_SIZE, PROT_READ|PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    LOG(1, "Initializing GS table at " << std::hex << buffer);

    gsTable->setTableAddress(buffer);

    address_t *array = static_cast<address_t *>(buffer);
    for(auto entry : CIter::children(gsTable)) {
        LOG(12, "    gs@[" << std::dec << entry->getIndex() << "] -> "
            << entry->getTarget()->getName());
        array[entry->getIndex()] = entry->getTarget()->getAddress();
    }

    arch_prctl(ARCH_SET_GS, reinterpret_cast<unsigned long>(buffer));
#endif
}

void ManageGS::setEntry(GSTable *gsTable, GSTableEntry::IndexType index,
    address_t value) {

    address_t *array = static_cast<address_t *>(gsTable->getTableAddress());
    array[index] = value;
}
