#include "jumptablebounds.h"
#include "exefile/exefile.h"
#include "analysis/jumptable.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP djumptable
#include "log/log.h"

void JumpTableBounds::visit(Module *module) {
    //LOG(1, "BEGIN jump table bounds pass");
    this->module = module;
    ElfMap *elfMap = ExeAccessor::map<ElfMap>(module);
    if(elfMap && elfMap->hasRelocations()) {
        visit(module->getJumpTableList());
    }
}

void JumpTableBounds::visit(JumpTableList *jumpTableList) {
    recurse(jumpTableList);

    // Note: we assume here that relocList is sorted by increasing address.
    auto relocList = module->getExeFile()->getRelocList();
    JumpTable *currentTable = nullptr;
    int count = 0;
    for(auto reloc : *relocList) {
        auto address = reloc->getAddress();
        auto it = tableMap.find(address);
        if(it != tableMap.end()) {
            if(currentTable) {
                // another table starts here, end the current one
                setEntries(currentTable, count);
                currentTable = nullptr;
            }

            // make sure the bounds for this table are not already known
            if((*it).second->getDescriptor()->getEntries() <= 0) {
                currentTable = (*it).second;
                count = 1;
                currentTable->getDescriptor()->setEntries(1);
            }
        }
        else if(currentTable) {
            int scale = currentTable->getDescriptor()->getScale();
            address_t computed = currentTable->getAddress() + count*scale;
            if(reloc->getAddress() == computed) {
                // this relocation follows on the previous ones
                count ++;
            }
            else {
                // end of this table's list of relocations
                setEntries(currentTable, count);
                currentTable = nullptr;
            }
        }
    }

    if(currentTable) {
        // last jump table was inferred
        setEntries(currentTable, count);
        currentTable = nullptr;
    }
}

void JumpTableBounds::visit(JumpTable *jumpTable) {
    tableMap[jumpTable->getAddress()] = jumpTable;
    //LOG(1, "got table at " << jumpTable->getAddress());
}

void JumpTableBounds::setEntries(JumpTable *jumpTable, int count) {
    // hard-coded minimum # of entries for GCC to make a jump table
    if(count >= 5) {
        LOG(1, "DEDUCED that table "
            << std::hex << jumpTable->getAddress()
            << " in [" << jumpTable->getFunction()->getName()
            << "] has " << std::dec << count << " entries");
        jumpTable->getDescriptor()->setEntries(count);
    }
}
