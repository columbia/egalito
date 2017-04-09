#include "jumptablepass.h"
#include "analysis/jumptable.h"
#include "chunk/jumptable.h"
#include "elf/elfspace.h"

void JumpTablePass::visit(Module *module) {
    auto jumpTableList = new JumpTableList();
    module->getChildren()->add(jumpTableList);
    module->setJumpTableList(jumpTableList);

    JumpTableSearch search;
    search.search(module);
    for(auto table : search.getTableList()) {
        auto jumpTable = new JumpTable(
            module->getElfSpace()->getElfMap(), table);
        module->getJumpTableList()->getChildren()->add(jumpTable);
    }
}
