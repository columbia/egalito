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
    auto elfSpace = module->getElfSpace();
    if (auto symbol = elfSpace->getSymbolList()->find(bbCountSymbolName.c_str())) {
        LOG(1, "Found Symbol!");
        this->module = module;
        bbCountSymbol = symbol;
        recurse(module);
    }
   
#endif
}

void BasicBlockCountPass::visit(Block *block) {
#ifdef ARCH_X86_64
    auto bbCountIncInstr = new Instruction();
    auto bbCountIncSemantic = new LinkedInstruction(bbCountIncInstr);

    DisasmHandle handle(true);
    // 48 ff 04 25 NN NN NN NN incq 0xNNNNNNNN
    auto bbCountIncInstrTemplate = DisassembleInstruction(handle).makeAssemblyPtr(
        std::vector<unsigned char>({0x48, 0xff, 0x04, 0x25, 0, 0, 0, 0}));
    bbCountIncSemantic->setAssembly(bbCountIncInstrTemplate);
    bbCountIncInstr->setSemantic(bbCountIncSemantic);
    auto bbCountSymbolLink = LinkFactory::makeDataLink(module, bbCountSymbol->getAddress(), true);
    assert(bbCountSymbolLink);
    bbCountIncSemantic->setLink(bbCountSymbolLink);
    bbCountIncSemantic->setIndex(0);

    ChunkMutator mutator(block);
    mutator.prepend(bbCountIncInstr);
    LOG(1, "Added Instruction!");
#endif
}
