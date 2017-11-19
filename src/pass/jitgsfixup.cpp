#include "jitgsfixup.h"
#include "switchcontext.h"
#include "chunk/concrete.h"
#include "conductor/conductor.h"
#include "disasm/disassemble.h"
#include "instr/linked-x86_64.h"
#include "instr/semantic.h"
#include "operation/find2.h"
#include "operation/mutator.h"
#include "cminus/print.h"
#include "snippet/hook.h"
#include "runtime/managegs.h"
#include "transform/generator.h"
#include "log/log.h"

GSTable *egalito_gsTable;
Chunk *egalito_gsCallback;
extern Sandbox *egalito_sandbox;

extern "C"
void egalito_jit_gs_fixup(unsigned long *address) {
    uint32_t offset = *reinterpret_cast<uint32_t *>(*address - 4);
    uint32_t index = egalito_gsTable->offsetToIndex(offset);

    egalito_printf("(JIT-fixup address=0x%lx index=%d ", *address, index);

    auto entry = egalito_gsTable->getAtIndex(index);
    if(entry) {
        entry->setLazyResolver(nullptr);
        auto target = entry->getTarget();
        egalito_printf("target=[%s])\n", target->getName().c_str());

        if(auto targetFunc = dynamic_cast<Function *>(target)) {
            egalito_sandbox->reopen();
            Generator generator(true);
            generator.copyFunctionToSandbox(targetFunc, egalito_sandbox);
            egalito_sandbox->finalize();
        }
        else {
            egalito_printf("JIT fixup error: target is not a function!\n");
        }

        ManageGS::setEntry(egalito_gsTable, index, target->getAddress());
        *address -= 8;  // size of call instruction; re-run it
    }
    else {
        egalito_printf("JIT jump error, target not known! Will likely crash.\n");
    }
}

extern "C"
void egalito_jit_gs_reset(void) {
    egalito_printf("resetting...\n");

    address_t *array = static_cast<address_t *>(
        egalito_gsTable->getTableAddress());

    for(auto entry : CIter::children(egalito_gsTable)) {
        entry->setLazyResolver(egalito_gsCallback);
        array[entry->getIndex()] = egalito_gsCallback->getAddress();
    }
}

JitGSFixup::JitGSFixup(Conductor *conductor, GSTable *gsTable)
    : conductor(conductor), gsTable(gsTable) {

}

void JitGSFixup::visit(Program *program) {
    auto lib = conductor->getLibraryList()->get("(egalito)");
    if(!lib) throw "JitGSFixup requires libegalito.so to be transformed";

    callback = ChunkFind2(conductor).findFunctionInModule(
        "egalito_hook_jit_fixup", lib->getElfSpace()->getModule());
    if(!callback) {
        throw "JitGSFixup can't find hook function";
    }

    SwitchContextPass switcher;
    callback->accept(&switcher);

    set_jit_fixup_hook(egalito_jit_gs_fixup);

    ::egalito_gsTable = gsTable;
    resetGSTable();

    ::egalito_gsCallback = callback;

    addResetCall();
}

void JitGSFixup::resetGSTable() {
    for(auto entry : CIter::children(gsTable)) {
        LOG(12, "set resolver for " << entry->getTarget()->getName());
        entry->setLazyResolver(callback);
    }
}

void JitGSFixup::addResetCall() {
    auto lib = conductor->getLibraryList()->get("(egalito)");
    if(!lib) throw "JitGSFixup requires libegalito.so to be transformed";

    auto reset = ChunkFind2(conductor).findFunctionInModule(
        "egalito_hook_jit_reset", lib->getElfSpace()->getModule());
    if(!reset) {
        throw "JitGSFixup can't find hook function";
    }

    auto libc = conductor->getLibraryList()->getLibc();
    if(!libc) throw "JitGSFixup requires libc.so to do continuous shuffling";

    auto write = ChunkFind2(conductor).findFunctionInModule(
        "__write", libc->getElfSpace()->getModule());
    if(!write) {
        throw "JitGSFixup can't find write function";
    }

    SwitchContextPass switcher;
    reset->accept(&switcher);

    set_jit_reset_hook(egalito_jit_gs_reset);

    Block *syscallBlock = nullptr;
    Instruction *syscall = nullptr;
    for(auto block : CIter::children(write)) {
        for(auto instr : CIter::children(block)) {
            if(auto assembly = instr->getSemantic()->getAssembly()) {
                if(assembly->getMnemonic() == "syscall") {
                    syscallBlock = block;
                    syscall = instr;
                    goto out;
                }
            }
        }
    }

    if(!syscall) return;

out:
    auto call = Disassemble::instruction({0xe8, 0, 0, 0, 0});
    auto semantic = call->getSemantic();
    auto cfi = dynamic_cast<ControlFlowInstruction *>(semantic);
    cfi->setLink(new ExternalNormalLink(reset));

    ChunkMutator(syscallBlock).insertAfter(syscall, call);
}
