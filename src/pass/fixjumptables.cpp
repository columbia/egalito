#include <iomanip>
#include "config.h"
#include "fixjumptables.h"
#include "chunk/chunkiter.h"
#include "chunk/dump.h"
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
#ifdef ARCH_X86_64
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

        switch(descriptor->getScale()) {
        case 4:
            LOG(1, "set slot " << std::hex << slot
                << " to value " << std::hex << target);
            *reinterpret_cast<int32_t *>(slot) = target;
            break;
        default:
            LOG(1, "Error: unknown jump table scale "
                << descriptor->getScale());
            break;
        }
    }
#elif defined(ARCH_AARCH64)
    // we only need to fix table entries when we modify the function
#endif
}
