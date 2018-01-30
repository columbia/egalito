#include <cassert>
#include "basicblockcount.h"
#include "chunk/concrete.h"
#include "chunk/dump.h"
#include "disasm/disassemble.h"
#include "disasm/handle.h"
#include "elf/elfspace.h"
#include "elf/symbol.h"
#include "instr/linked-x86_64.h"
#include "operation/mutator.h"
#include "analysis/frametype.h"
#include "log/log.h"

void BasicBlockCountPass::visit(Module *module) {
#ifdef ARCH_X86_64
    LOG(1, "searching for symbol 'my_basic_block_counter'");
    //if (auto dataVariable = module->getDataRegionList()->findVariable(bbCountSymbolName) ) {

    //for(auto sym : *module->getElfSpace()->getSymbolList()) {
    //    LOG(1, "sym [" << sym->getName() << "]");
    //}

    Program *program = static_cast<Program *>(module->getParent());
    //auto lib = program->getLibraryList()->byRole(Library::ROLE_SUPPORT);
    auto lib = program->getLibraryList()->find("libbbcount.so");
    if(!lib) {
        LOG(0, "Can't find libbbcount.so!");
        return;
    }
    this->libModule = lib->getModule();
    if(auto symbol = libModule->getElfSpace()->getSymbolList()->find(bbCountSymbolName)) {
        LOG(1, "Found basic block count symbol ["
            << symbol->getName() << "] at " << symbol->getAddress());
        this->counterSymbol = symbol;
        this->module = module;
    }

    recurse(module);
#endif
}

void BasicBlockCountPass::visit(Function *function) {
    FrameType frame(function);
    this->hasFrame = frame.createsFrame()
        && (frame.getSetSPInstr() != nullptr);

    LOG(0, "BasicBlockCountPass: does ["
        << function->getName() << "] create a frame? "
        << (hasFrame ? 'y' : 'n'));

    recurse(function);
    ChunkMutator(function, true);
}

void BasicBlockCountPass::visit(Block *block) {
#ifdef ARCH_X86_64
    if(!counterSymbol) {
        LOG(1, "counter symbol not found, skipping basic block counts");
        return;
    }

    // pushfd
    auto saveFlagsIns = Disassemble::instruction({0x9c});

    // popfd
    auto restoreFlagsIns = Disassemble::instruction({0x9d});

    // lea -0x80(%rsp), rsp
    auto subIns = Disassemble::instruction({0x48, 0x8d, 0x64, 0x24, 0x80});

    // lea 0x80(%rsp), rsp
    auto addIns = Disassemble::instruction({0x48, 0x8d, 0xa4, 0x24, 0x80, 0x00, 0x00, 0x00});

    //LOG(1, "adding bbcount instr to " << block->getName());
    //ChunkDumper dump;
    //block->accept(&dump);

    // 48 ff 05 00 0f 00 00 	incq   0xf00(%rip)
    static DisasmHandle handle(true);
    auto instr = new Instruction();
    auto semantic = new LinkedInstruction(instr);
    auto assembly = DisassembleInstruction(handle).makeAssemblyPtr(
        (std::vector<unsigned char>){0x48, 0xff, 0x05, 0, 0, 0, 0});
    semantic->setAssembly(assembly);
    instr->setSemantic(semantic);

    auto dataRegionList = libModule->getDataRegionList();
    auto link = dataRegionList->createDataLinkFromOriginalAddress(
        counterSymbol->getAddress(), libModule, true);
    assert(link != nullptr);
    semantic->setLink(link);
    semantic->setIndex(0);

    Instruction *firstChild = nullptr;
    if(block->getChildren()->getIterable()->getCount() > 0) {
        firstChild = block->getChildren()->getIterable()->get(0);
    }
#if 0
    ChunkMutator(block).insertBeforeJumpTo(firstChild, subIns);
    // firstChild and subIns semantics got swapped...
    ChunkMutator(block).insertAfter(firstChild, saveFlagsIns);
    ChunkMutator(block).insertAfter(saveFlagsIns, instr);
    ChunkMutator(block).insertAfter(instr, restoreFlagsIns);
    ChunkMutator(block).insertAfter(restoreFlagsIns, addIns);
#elif 0
    ChunkMutator(block).insertBeforeJumpTo(firstChild, addIns);
    // firstChild and subIns semantics got swapped...
    ChunkMutator(block).insertBeforeJumpTo(firstChild, restoreFlagsIns);
    ChunkMutator(block).insertBeforeJumpTo(firstChild, instr);
    ChunkMutator(block).insertBeforeJumpTo(firstChild, saveFlagsIns);
    ChunkMutator(block).insertBeforeJumpTo(firstChild, subIns);
#else
    if(hasFrame) {
        ChunkMutator(block).insertAfter(firstChild, saveFlagsIns);
        ChunkMutator(block).insertAfter(saveFlagsIns, instr);
        ChunkMutator(block).insertAfter(instr, restoreFlagsIns);

        //ChunkMutator(block).insertAfter(firstChild, saveFlagsIns);
        //ChunkMutator(block).insertAfter(saveFlagsIns, restoreFlagsIns);
    }
    else {
        ChunkMutator(block).insertAfter(firstChild, subIns);
        ChunkMutator(block).insertAfter(subIns, saveFlagsIns);
        ChunkMutator(block).insertAfter(saveFlagsIns, instr);
        ChunkMutator(block).insertAfter(instr, restoreFlagsIns);
        ChunkMutator(block).insertAfter(restoreFlagsIns, addIns);
    }
#endif

    //LOG(1, "done with " << block->getName());
    //block->accept(&dump);
#endif
}
