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
        auto jumpTable = new JumpTable(
            module->getElfSpace()->getElfMap(), descriptor);

        int count = jumpTable->getEntryCount();
        /*if(count < 0) {
            LOG(1, "Warning: can't make jump table entries for table "
                << jumpTable->getAddress() << " in ["
                << descriptor->getFunction()->getName() << "], bounds are not known");
            continue;
        }*/

        LOG(1, "constructing jump table at " << jumpTable->getAddress() << " in ["
            << descriptor->getFunction()->getName() << "] with " << count << " entries");
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

        jumpTableList->getChildren()->add(jumpTable);
    }
}
