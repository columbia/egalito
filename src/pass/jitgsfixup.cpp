#include "jitgsfixup.h"
#include "switchcontext.h"
#include "chunk/concrete.h"
#include "conductor/conductor.h"
#include "conductor/setup.h"
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
extern ConductorSetup *egalito_conductor_setup;

extern "C"
size_t egalito_jit_gs_fixup(size_t offset) {
    size_t index = egalito_gsTable->offsetToIndex(offset);
    egalito_printf("(JIT-fixup index=%d ", (int)index);

    auto target = ManageGS::resolve(egalito_gsTable, index);
    egalito_printf("target=[%s])\n", target->getName().c_str());

    Function *targetFunction = dynamic_cast<Function *>(target);
    PLTTrampoline *targetTrampoline = nullptr;
    Chunk *targetChunk = targetFunction;
    if(!targetFunction) {
        if(dynamic_cast<Instruction *>(target)) {
            targetFunction = dynamic_cast<Function *>(
                target->getParent()->getParent());
            targetChunk = targetFunction;
        }
        else if(auto trampoline = dynamic_cast<PLTTrampoline *>(target)) {
            targetTrampoline = trampoline;
            targetChunk = trampoline;
        }
        else {
            egalito_printf("parent = %s\n",
                   target->getParent()->getParent()->getName().c_str());

            egalito_printf("JIT error, target not known!\n");
            while(1);
        }
    }

#if 0
    egalito_conductor_setup->flipSandboxEnd();
#endif

    if(targetChunk) {
        auto gsEntry = egalito_gsTable->getEntryFor(targetChunk);
        if(gsEntry && !gsEntry->mapped()) {
            auto sandbox = egalito_conductor_setup->getSandbox();
            sandbox->reopen();
            Generator generator(true);
            if(targetFunction) {
                generator.copyFunctionToSandbox(targetFunction, sandbox);
            }
            else if(targetTrampoline) {
                generator.copyPLTToSandbox(targetTrampoline, sandbox);
            }
            sandbox->finalize();
        }
    }

    ManageGS::setEntry(egalito_gsTable, index, target->getAddress());
    return offset;
}

extern "C"
void egalito_jit_gs_reset(void) {
    egalito_printf("resetting...\n");
    ManageGS::resetEntries(egalito_gsTable, egalito_gsCallback);
}

JitGSFixup::JitGSFixup(Conductor *conductor, GSTable *gsTable)
    : conductor(conductor), gsTable(gsTable) {

}

void JitGSFixup::visit(Program *program) {
    auto lib = program->getEgalito();
    if(!lib) throw "JitGSFixup requires libegalito.so to be transformed";

    callback = ChunkFind2(conductor).findFunctionInModule(
        "egalito_hook_jit_fixup", lib->getElfSpace()->getModule());
    if(!callback) {
        throw "JitGSFixup can't find hook function";
    }
    ::egalito_gsCallback = callback;

    ::egalito_gsTable = gsTable;
    // ManageGS methods cannot be used until 'runtime', because there is no
    // buffer yet
    for(auto entry : CIter::children(gsTable)) {
        entry->setLazyResolver(callback);
    }

    //addResetCall();
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

#ifdef ARCH_X86_64
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
#elif defined(ARCH_AARCH64)
    LOG(1, "JitGSFixup::addResetCall NYI");
#endif
}
