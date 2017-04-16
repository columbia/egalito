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
    auto elfMap = module->getElfSpace()->getElfMap();

    JumpTableSearch search;
    search.search(module);
    for(auto descriptor : search.getTableList()) {
        // this constructor automatically creates JumpTableEntry children

        LOG(1, "constructing jump table at "
            << descriptor->getAddress() << " in ["
            << descriptor->getFunction()->getName() << "] with "
            << descriptor->getEntries() << " entries");

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
        for(int i = 0; i < count; i ++) {
            auto address = jumpTable->getAddress() + i*descriptor->getScale();
            auto p = elfMap->getCopyBaseAddress() + address;
            auto value = *reinterpret_cast<int *>(p);
            value += descriptor->getAddress();  // for relative jump tables
            LOG(2, "    jump table entry " << i << " value " << value);

            Chunk *inner = ChunkFind().findInnermostInsideInstruction(
                module->getFunctionList(), value);
            Link *link = nullptr;
            if(inner) {
                LOG(3, "        resolved to " << inner->getName());
                link = new NormalLink(inner);
            }
            else {
                LOG(3, "        unresolved at " << value);
                link = new UnresolvedLink(value);
            }
            auto entry = new JumpTableEntry(link);
            entry->setPosition(PositionFactory::getInstance()
                ->makeAbsolutePosition(address));
            jumpTable->getChildren()->add(entry);
        }
    }
}
