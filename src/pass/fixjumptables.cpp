#include <iomanip>
#include "config.h"
#include "fixjumptables.h"
#include "chunk/chunkiter.h"
#include "chunk/dump.h"
#include "elf/elfspace.h"
#include "analysis/jumptable.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP djumptable
#include "log/log.h"

void FixJumpTablesPass::visit(Module *module) {
    this->module = module;
    if(module->getJumpTableList()) {
        recurse(module->getJumpTableList());
    }
}

void FixJumpTablesPass::visit(JumpTableList *jumpTableList) {
    if(!jumpTableList) return;
    recurse(jumpTableList);
}

void FixJumpTablesPass::visit(JumpTable *jumpTable) {
    auto descriptor = jumpTable->getDescriptor();

    LOG(1, "fixing jump table...");
    IF_LOG(1) {
        ChunkDumper dumper;
        jumpTable->accept(&dumper);
    }

    for(auto entry : CIter::children(jumpTable)) {
        address_t slot = entry->getDataVariable()->getAddress();
        address_t target = entry->getLink()->getTargetAddress();

        // for relative jump tables (always the case right now)
        target -= descriptor->getTargetBaseLink()->getTargetAddress();

        LOG(1, "set slot " << std::hex << slot
            << " to value " << std::hex << target);
        switch(descriptor->getScale()) {
        case 4:
            *reinterpret_cast<int32_t *>(slot) = target;
            break;
        case 2:
            *reinterpret_cast<int16_t *>(slot) = target;
            break;
        case 1:
            *reinterpret_cast<int8_t *>(slot) = target;
            break;
        default:
            LOG(1, "Error: unknown jump table scale "
                << descriptor->getScale());
            break;
        }
    }
}
