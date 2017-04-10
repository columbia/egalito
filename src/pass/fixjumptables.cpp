#include <iomanip>
#include "fixjumptables.h"
#include "chunk/chunkiter.h"
#include "chunk/dump.h"
#include "elf/elfspace.h"
#include "analysis/jumptable.h"
#include "log/log.h"

void FixJumpTablesPass::visit(Module *module) {
    this->module = module;
    recurse(module->getJumpTableList());
}

void FixJumpTablesPass::visit(JumpTableList *jumpTableList) {
    if(!jumpTableList) return;
    recurse(jumpTableList);
}

void FixJumpTablesPass::visit(JumpTable *jumpTable) {
    auto elfMap = module->getElfSpace()->getElfMap();
    auto descriptor = jumpTable->getDescriptor();

    LOG(1, "fixing jump table...");
    ChunkDumper dumper;
    jumpTable->accept(&dumper);

    for(auto entry : CIter::children(jumpTable)) {
        auto link = entry->getLink();
        address_t target = link->getTargetAddress();
        address_t slot = elfMap->getBaseAddress() + entry->getAddress();

        // for relative jump tables
        target -= elfMap->getBaseAddress() + descriptor->getAddress();

        switch(descriptor->getScale()) {
        case 4:
            LOG(1, "set slot " << std::hex << slot
                << " to point to " << std::hex << target);
            *reinterpret_cast<uint32_t *>(slot) = target;
            break;
        default:
            LOG(1, "Error: unknown jump table scale "
                << descriptor->getScale());
            break;
        }
    }
}
