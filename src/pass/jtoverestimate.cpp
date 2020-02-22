#include <sys/mman.h>
#include "jtoverestimate.h"
#include "elf/elfspace.h"
#include "operation/find.h"
#include "analysis/jumptable.h"
#include "jumptablepass.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP djumptable
#include "log/log.h"

void JumpTableOverestimate::visit(Module *module) {
    this->module = module;
    visit(module->getJumpTableList());
}

void JumpTableOverestimate::visit(JumpTableList *jumpTableList) {
    recurse(jumpTableList);

    for(auto it = tableMap.begin(); it != tableMap.end(); it ++) {
        JumpTable *currentTable = (*it).second;
        if(currentTable->getDescriptor()->getEntries() > 0) {
            // bounds for this table are already known
            continue;
        }

        address_t address = currentTable->getDescriptor()->getAddress();

        auto contentSection =
            currentTable->getDescriptor()->getContentSection();
        if(!contentSection) continue;
        auto tableSection =
            module->getElfSpace()->getElfMap()->findSection(
                contentSection->getName().c_str());
        auto tableReadPtr = module->getElfSpace()->getElfMap()
            ->getSectionReadPtr<unsigned char *>(tableSection);

        int scale = currentTable->getDescriptor()->getScale();
        for(int count = 1; ; count ++) {
            address_t computed = address + count*scale;
            if(tableMap.find(computed) != tableMap.end()) {
                // reached another jump table's entries, stop looking
                setEntries(currentTable, count);
                break;
            }

            address_t offset = tableSection->convertVAToOffset(computed);
            int value = *reinterpret_cast<int *>(tableReadPtr + offset);

            //if(!value) continue;  // zero entry, not used?

            //LOG(1, "looks like value is " << std::hex << value);

            // for relative jump tables
            value += address;

            auto next = it;
            next ++;
            if(next == tableMap.end()) {
                /* Only care about value-based estimation for last jump table case.
                    Note: this doesn't work for cross-function jump tables,
                    which may happen in e.g. LTO-optimized function pieces.

                    This occurs in Debian stable python2.7 in the function
                    symtable_visit_expr.lto_priv.1839.
                */
                auto function = currentTable->getDescriptor()->getFunction();
                if(!function->getRange().contains(value)) {
                    // this entry would be outside the function, stop looking
                    setEntries(currentTable, count);
                    break;
                }
            }
            else {
                /* Make sure we target *some* instruction, even if it's in a
                    different function. See comment above.
                */
                auto found = ChunkFind().findInnermostInsideInstruction(
                    module->getFunctionList(), value);
                if(!found) {
                    // this entry would be outside all functions
                    setEntries(currentTable, count);
                    break;
                }
            }
        }
    }
}

void JumpTableOverestimate::visit(JumpTable *jumpTable) {
    tableMap[jumpTable->getAddress()] = jumpTable;
}

void JumpTableOverestimate::setEntries(JumpTable *jumpTable, int count) {
    LOG(5, "APPARENTLY, table " << std::hex << jumpTable->getAddress()
            << " in [" << jumpTable->getFunction()->getName()
            << "] has " << std::dec << count << " entries");
    int made = JumpTablePass(module).makeChildren(jumpTable, count);
    if(made != count) {
        LOG(5, "    BUT makeChildren only found " << made
            << " children, updating bound " << std::hex
            << jumpTable->getAddress()
            << " in [" << jumpTable->getFunction()->getName()
            << "] has " << std::dec << count << " entries");
        count = made;
    }
    jumpTable->getDescriptor()->setEntries(count);
}
