#include <cassert>
#include "basicblockcount.h"
#include "chunk/concrete.h"
#include "disasm/disassemble.h"
#include "elf/elfspace.h"
#include "instr/linked-x86_64.h"
#include "operation/mutator.h"
#include "log/log.h"

void BasicBlockCountPass::visit(Module *module) {
#ifdef ARCH_X86_64
    LOG(1, "searching for symbol 'my_basic_block_counter'");
    if (auto dataVariable = module->getDataRegionList()->findVariable(bbCountSymbolName) ) {
        LOG(1, "Found Variable!");
        counterDataVariable = dataVariable;
        this->module = module;
        recurse(module);
    }
   
#endif
}

void BasicBlockCountPass::visit(Block *block) {
#ifdef ARCH_X86_64
#endif
}
