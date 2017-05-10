#include <algorithm>
#include "jumptablepass.h"
#include "analysis/jumptable.h"
#include "chunk/jumptable.h"
#include "operation/find.h"
#include "elf/elfspace.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP djumptable
#include "log/log.h"

void JumpTablePass::visit(Module *module) {
    this->module = module;
    auto jumpTableList = new JumpTableList();
    module->getChildren()->add(jumpTableList);
    module->setJumpTableList(jumpTableList);
    visit(jumpTableList);
}

void JumpTablePass::visit(JumpTableList *jumpTableList) {
    JumpTableSearch search;
    search.search(module);
    for(auto descriptor : search.getTableList()) {
        // this constructor automatically creates JumpTableEntry children

        LOG(1, "constructing jump table at 0x"
            << std::hex << descriptor->getAddress() << " in ["
            << descriptor->getFunction()->getName() << "] with "
            << std::dec << descriptor->getEntries() << " entries, each of size "
            << std::dec << descriptor->getScale());

        JumpTable *jumpTable = nullptr;
        int count = -1;
        auto it = tableMap.find(descriptor->getAddress());
        if(it != tableMap.end()) {
            // already exists
            jumpTable = (*it).second;
            auto otherCount = jumpTable->getEntryCount();
            auto thisCount = descriptor->getEntries();
            if(otherCount < 0 && thisCount >= 0) {
                count = descriptor->getEntries();
                delete jumpTable->getDescriptor();
                jumpTable->setDescriptor(descriptor);
            }
            else if(otherCount >= 0 && thisCount >= 0) {
                if(otherCount != thisCount) {
                    LOG(0, "WARNING: overlapping jump tables at "
                        << std::hex << descriptor->getAddress() << " in ["
                        << descriptor->getFunction()->getName()
                        << "] with different sizes! " << std::dec
                        << otherCount << " vs " << thisCount);
                    count = std::max(otherCount, thisCount);
                    if(thisCount > otherCount) {
                        delete jumpTable->getDescriptor();
                        jumpTable->setDescriptor(descriptor);
                    }
                }
            }
        }
        else {
            jumpTable = new JumpTable(
                module->getElfSpace()->getElfMap(), descriptor);
            count = jumpTable->getEntryCount();
            jumpTableList->getChildren()->add(jumpTable);
        }
        tableMap[jumpTable->getAddress()] = jumpTable;

        // create JumpTableEntry's
        makeChildren(jumpTable, count);
    }
}

void JumpTablePass::makeChildren(JumpTable *jumpTable, int count) {
    auto elfMap = module->getElfSpace()->getElfMap();
    auto descriptor = jumpTable->getDescriptor();
    for(int i = 0; i < count; i ++) {
        auto address = jumpTable->getAddress() + i*descriptor->getScale();
        auto p = elfMap->getCopyBaseAddress() + address;
        ptrdiff_t value;
        switch(descriptor->getScale()) {
        case 1:
            value = *reinterpret_cast<int8_t *>(p);
            break;
        case 2:
            value = *reinterpret_cast<int16_t *>(p);
            break;
        case 4:
        default:
            value = *reinterpret_cast<int32_t *>(p);
            break;
        }
#ifdef ARCH_AARCH64
        value *= 4;
#endif
        address_t target = descriptor->getTargetBaseAddress() + value;
        LOG(2, "    jump table entry " << i << " @ 0x" << std::hex << target);

        Chunk *inner = ChunkFind().findInnermostInsideInstruction(
            module->getFunctionList(), target);
        Link *link = nullptr;
        if(inner) {
            LOG(3, "        resolved to 0x" << std::hex << inner->getName());
            link = new NormalLink(inner);
        }
        else {
            LOG(3, "        unresolved at 0x" << std::hex << target);
            link = new UnresolvedLink(target);
        }
        auto entry = new JumpTableEntry(link);
        entry->setPosition(PositionFactory::getInstance()
            ->makeAbsolutePosition(address));
        jumpTable->getChildren()->add(entry);
    }
}
