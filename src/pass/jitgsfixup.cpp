#include <pthread.h>
#include <cstring>
#include <cassert>
#include "jitgsfixup.h"
#include "chunk/concrete.h"
#include "chunk/tls.h"
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
#include "transform/sandbox.h"
#include "util/explicit_bzero.h"
#include "util/feature.h"
#include "util/timing.h"
#include "log/log.h"

Chunk *egalito_gsCallback __attribute__((weak));

extern "C"
size_t egalito_jit_gs_fixup(size_t offset) {
    auto gsTable = EgalitoTLS::getGSTable();
    size_t index = gsTable->offsetToIndex(offset);
    //egalito_printf("index=%d\n", (int)index);
    //egalito_printf("(JIT-fixup index=%d ", (int)index);

    auto target = ManageGS::resolve(gsTable, index);
    //egalito_printf("target=[%s])\n", target->getName().c_str());

    Function *targetFunction = dynamic_cast<Function *>(target);
    PLTTrampoline *targetTrampoline = dynamic_cast<PLTTrampoline *>(target);

    address_t address;
    if(targetFunction || targetTrampoline) {
        auto sandbox = EgalitoTLS::getSandbox();
        sandbox->reopen();
        Generator generator(true);
        if(targetFunction) {
            generator.instantiate(targetFunction, sandbox);
        }
        else {
            generator.instantiate(targetTrampoline, sandbox);
        }
        sandbox->finalize();
        address = target->getAddress();
        PositionManager::setAddress(target, 0);
    }
    else {
        if(dynamic_cast<Instruction *>(target)) {
            auto function = target->getParent()->getParent();
            auto entry = gsTable->getEntryFor(function);
            // during JIT-shuffling, function's address is 0
            address = target->getAddress() - function->getAddress()
                + ManageGS::getEntry(entry->getOffset());
        }
        else {
            //egalito_printf("JIT error, target not known!\n");
            while(1);
        }
    }

    //egalito_printf("%lx\n", address);
    ManageGS::setEntry(gsTable, index, address);
    return offset;
}

extern "C"
void egalito_jit_gs_init(ShufflingSandbox *sandbox, GSTable *gsTable) {
    sandbox->reopen();
    sandbox->recreate();
    Generator generator(true);
    for(auto gsEntry : CIter::children(gsTable)) {
        if(gsEntry->getIndex() == gsTable->getJITStartIndex()) break;

        auto target = gsEntry->getTarget();
        if(auto f = dynamic_cast<Function *>(target)) {
            generator.instantiate(f, sandbox);
        }
        else if(auto trampoline = dynamic_cast<PLTTrampoline *>(target)) {
            generator.instantiate(trampoline, sandbox);
        }
    }
    sandbox->finalize();
    ManageGS::resetEntries(gsTable, egalito_gsCallback);
    explicit_bzero(EgalitoTLS::getJITAddressTable(), JIT_TABLE_SIZE);
    sandbox->flip();
    sandbox->reopen();
    sandbox->recreate();
    sandbox->finalize();
}

extern "C"
void egalito_jit_gs_reset(void) {
#if 0
    EgalitoTiming t2("egalito_jit_gs_reset");
    static EgalitoTiming *t = nullptr;
    if(t) {
        delete t;
    }
    t = new EgalitoTiming("from previous reset");
#endif
    auto counter = EgalitoTLS::getJITResetCounter();
    auto threshold = EgalitoTLS::getJITResetThreshold();
    counter++;
    if(counter < threshold) {
        EgalitoTLS::setJITResetCounter(counter);
        return;
    }
    EgalitoTLS::setJITResetCounter(0);
    //egalito_printf("resetting...\n");
    auto sandbox = EgalitoTLS::getSandbox();
    auto gsTable = EgalitoTLS::getGSTable();

    egalito_jit_gs_init(sandbox, gsTable);
}

extern "C"
void egalito_jit_gs_setup_thread(void) {
    ManageGS::setGS(EgalitoTLS::getGSTable());
    volatile size_t *barrier = EgalitoTLS::getBarrier();
    *barrier = 1;
    EgalitoTLS::setBarrier(nullptr);
}

JitGSFixup::JitGSFixup(Conductor *conductor, GSTable *gsTable)
    : conductor(conductor), gsTable(gsTable) {

}

void JitGSFixup::addAfterFirstSyscall(const char *name, Module *module,
    Chunk *target) {

    addAfterSyscall(name, module, target, true);
}

void JitGSFixup::addAfterEverySyscall(const char *name, Module *module,
    Chunk *target) {

    addAfterSyscall(name, module, target, false);
}

void JitGSFixup::visit(Program *program) {
    auto lib = program->getEgalito();
    if(!lib) throw "JitGSFixup requires libegalito.so to be transformed";

    callback = ChunkFind2(conductor).findFunctionInModule(
        "egalito_hook_jit_fixup", lib);
    assert(callback);
    ::egalito_gsCallback = callback;

    if(isFeatureEnabled("EGALITO_USE_SHUFFLING")) {
        addResetCalls();
    }

    auto hook = ChunkFind2(conductor).findFunctionInModule(
        "egalito_hook_after_clone_syscall", lib);
    assert(hook);
    addAfterFirstSyscall("clone", program->getLibc(), hook);
}

void JitGSFixup::addResetCalls() {
    auto lib = conductor->getProgram()->getEgalito();
    if(!lib) throw "JitGSFixup requires libegalito.so to be transformed";

    // this can only be hooked around function call or system call
    // as it assumes that r11 is clobberable.
    auto reset = ChunkFind2(conductor).findFunctionInModule(
        "egalito_hook_jit_reset_on_syscall", lib);
    if(!reset) {
        throw "JitGSFixup can't find hook function";
    }

    if(auto libc = conductor->getProgram()->getLibc()) {
        // for nginx, reply uses writev, logging uses 'write'
        addAfterEverySyscall("writev", libc, reset);
#if 0
        addAfterEverySyscall("write", libc, reset);
        addAfterEverySyscall("_IO_file_write", libc, reset);
#endif
    }

#if 0
    if(auto libpthread = conductor->getProgram()->getLibraryList()
        ->find("libpthread.so.0")) {

        addAfterEverySyscall("write", libpthread->getModule(), reset);
    }
#endif
}

void JitGSFixup::addAfterSyscall(const char *name, Module *module,
    Chunk *target, bool firstOnly) {

    auto function = ChunkFind2(conductor).findFunctionInModule(name, module);
    assert(function);

    bool next = false;
    for(auto b : CIter::children(function)) {
        for(auto i : CIter::children(b)) {
            if(next) {
                addAfter(i, b, target);
                if(firstOnly) {
                    return;
                }
                else {
                    next = false;
                }
            }
            if(auto assembly = i->getSemantic()->getAssembly()) {
                if(assembly->getMnemonic() == "syscall") {
                    next = true;
                }
            }
        }
    }
}

void JitGSFixup::addAfter(Instruction *instruction, Block *block,
    Chunk *target) {

#ifdef ARCH_X86_64
    // this modification must follow index-based ABI
    DisasmHandle handle(true);

    // jmpq *%gs:Offset
    auto jmpq = new Instruction();
    auto semantic = new LinkedInstruction(jmpq);
    std::vector<unsigned char> bin{0x65, 0xff, 0x24, 0x25, 0, 0, 0, 0};
    semantic->setAssembly(DisassembleInstruction(handle).makeAssemblyPtr(bin));
    auto gsEntry = gsTable->makeJITEntryFor(target);
    semantic->setLink(new GSTableLink(gsEntry));
    semantic->setIndex(0);
    jmpq->setSemantic(semantic);

    // push RA1 = gs offset
    std::vector<unsigned char > pushB1{0x68, 0, 0, 0, 0};
    auto gsEntrySelf = gsTable->makeJITEntryFor(block->getParent());
    uint32_t tmp1 = gsEntrySelf->getOffset();
    std::memcpy(&pushB1[1], &tmp1, 4);
    auto push1 = DisassembleInstruction(handle).instruction(pushB1);

    // movl instr offset, 0x4(%rsp)
    auto movRA = new Instruction();
    auto semantic2 = new LinkedInstruction(movRA);
    std::vector<unsigned char> movB{0xc7, 0x44, 0x24, 0x04, 0, 0, 0, 0};
    semantic2->setAssembly(DisassembleInstruction(handle).makeAssemblyPtr(movB));
    semantic2->setLink(new DistanceLink(block->getParent(), jmpq));
    semantic2->setIndex(0);
    movRA->setSemantic(semantic2);

    // movd offset = 0x4(%rip), %mm1
    auto movOffset = DisassembleInstruction(handle).instruction(
        std::vector<unsigned char>({0x0f, 0x6e, 0x0d, 0x04, 0, 0, 0}));

    ChunkMutator m(block);
    m.insertBeforeJumpTo(instruction, push1);
    m.insertAfter(instruction, movRA);
    m.insertAfter(movRA, movOffset);
    m.insertAfter(movOffset, jmpq);
    // we may need to split the block
#elif defined(ARCH_AARCH64)
    LOG(1, "JitGSFixup::addResetCall NYI");
#endif
}
