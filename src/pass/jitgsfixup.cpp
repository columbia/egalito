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
#include "log/log.h"

Chunk *egalito_gsCallback;

extern "C"
size_t egalito_jit_gs_fixup(size_t offset) {
    auto gsTable = EgalitoTLS::getGSTable();
    size_t index = gsTable->offsetToIndex(offset);
    egalito_printf("(JIT-fixup index=%d ", (int)index);

    auto target = ManageGS::resolve(gsTable, index);
    egalito_printf("target=[%s])\n", target->getName().c_str());

    Function *targetFunction = dynamic_cast<Function *>(target);
    PLTTrampoline *targetTrampoline = nullptr;
    Chunk *targetChunk = targetFunction;
    if(!targetFunction) {
        if(dynamic_cast<Instruction *>(target)) {
            targetFunction = dynamic_cast<Function *>(
                target->getParent()->getParent());
            //targetChunk = targetFunction;
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

    // instantiate does not set resolver to nullptr, so resolved() does not
    // work

    if(targetChunk) {
        auto sandbox = EgalitoTLS::getSandbox();
        sandbox->reopen();
        Generator generator(true);
        if(targetFunction) {
            generator.instantiate(targetFunction, sandbox);
            egalito_printf("%lx\n", targetFunction->getAddress());
        }
        else if(targetTrampoline) {
            generator.instantiate(targetTrampoline, sandbox);
            egalito_printf("%lx\n", targetTrampoline->getAddress());
        }
        sandbox->finalize();
    }
    else {
        egalito_printf("    not jitting\n");
    }

    ManageGS::setEntry(gsTable, index, target->getAddress());
    return offset;
}

extern "C"
void egalito_jit_gs_reset(void) {
    egalito_printf("resetting...\n");
    auto gsTable = EgalitoTLS::getGSTable();
    auto sandbox = EgalitoTLS::getSandbox();

    sandbox->reopen();
    sandbox->recreate();    // better if we only clear the unused after copy?
    Generator generator(true);
    for(auto gsEntry : CIter::children(gsTable)) {
        if(dynamic_cast<GSTableResolvedEntry *>(gsEntry)) {
            auto target = gsEntry->getTarget();
            egalito_printf("%s ", target->getName().c_str());
            if(auto f = dynamic_cast<Function *>(target)) {
                generator.instantiate(f, sandbox);
                egalito_printf("%lx\n", f->getAddress());
            }
            else if(auto trampoline = dynamic_cast<PLTTrampoline *>(target)) {
                generator.instantiate(trampoline, sandbox);
                egalito_printf("%lx\n", trampoline->getAddress());
            }
            else {
                break;
            }
        }
        else {
            break;
        }
    }
    sandbox->finalize();

    ManageGS::resetEntries(gsTable, egalito_gsCallback);
    sandbox->flip();
    sandbox->reopen();
    sandbox->recreate();
    sandbox->finalize();
}

extern "C"
void egalito_jit_gs_transition(ShufflingSandbox *sandbox, GSTable *gsTable) {
    sandbox->reopen();
    //sandbox->recreate();    // better if we only clear the unused after copy?
    Generator generator(true);
    for(auto gsEntry : CIter::children(gsTable)) {
        if(dynamic_cast<GSTableResolvedEntry *>(gsEntry)) {
            auto target = gsEntry->getTarget();
            if(auto f = dynamic_cast<Function *>(target)) {
                generator.instantiate(f, sandbox);
            }
            else if(auto trampoline = dynamic_cast<PLTTrampoline *>(target)) {
                generator.instantiate(trampoline, sandbox);
            }
            else {
                break;
            }
        }
        else {
            break;
        }
    }
    sandbox->finalize();

    ManageGS::resetEntries(gsTable, egalito_gsCallback);
    sandbox->flip();
    //sandbox->reopen();
    //sandbox->recreate();
    sandbox->finalize();
}

extern "C"
void egalito_jit_gs_setup_thread(void) {
    ManageGS::setGS(EgalitoTLS::getGSTable());
}

JitGSFixup::JitGSFixup(Conductor *conductor, GSTable *gsTable)
    : conductor(conductor), gsTable(gsTable) {

}

void JitGSFixup::visit(Program *program) {
    auto lib = program->getEgalito();
    if(!lib) throw "JitGSFixup requires libegalito.so to be transformed";

    callback = ChunkFind2(conductor).findFunctionInModule(
        "egalito_hook_jit_fixup", lib);
    assert(callback);
    ::egalito_gsCallback = callback;

    // ManageGS methods cannot be used until 'runtime', because there is no
    // buffer yet
    for(auto entry : CIter::children(gsTable)) {
        entry->setLazyResolver(callback);
    }

    addResetCalls();

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
        addAfterFirstSyscall("write", libc, reset);
    }

    if(auto libpthread = conductor->getProgram()->getLibraryList()
        ->find("libpthread.so.0")) {

        addAfterFirstSyscall("write", libpthread->getModule(), reset);
    }
}

void JitGSFixup::addAfterFirstSyscall(const char *name, Module *module,
    Chunk *reset) {

#ifdef ARCH_X86_64
    auto function = ChunkFind2(conductor).findFunctionInModule(name, module);
    assert(function);

    Block *block = nullptr;
    Instruction *instr = nullptr;
    bool next = false;
    for(auto b : CIter::children(function)) {
        for(auto i : CIter::children(b)) {
            if(next) {
                block = b;
                instr = i;
                goto out;
            }
            if(auto assembly = i->getSemantic()->getAssembly()) {
                if(assembly->getMnemonic() == "syscall") {
                    next = true;
                }
            }
        }
    }

    if(!instr) return;

out:
    // this modification must follow index-based ABI
    DisasmHandle handle(true);

    // jmpq *%gs:Offset
    auto jmpq = new Instruction();
    auto semantic = new LinkedInstruction(jmpq);
    std::vector<unsigned char> bin{0x65, 0xff, 0x24, 0x25, 0, 0, 0, 0};
    semantic->setAssembly(DisassembleInstruction(handle).makeAssemblyPtr(bin));
    auto gsEntry = gsTable->makeEntryFor(reset);
    semantic->setLink(new GSTableLink(gsEntry));
    semantic->setIndex(0);
    jmpq->setSemantic(semantic);

    // push RA1 = gs offset
    std::vector<unsigned char > pushB1{0x68, 0, 0, 0, 0};
    auto gsEntrySelf = gsTable->makeEntryFor(block->getParent());
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
    m.insertBeforeJumpTo(instr, push1);
    m.insertAfter(instr, movRA);
    m.insertAfter(movRA, movOffset);
    m.insertAfter(movOffset, jmpq);
    // we may need to split the block
#elif defined(ARCH_AARCH64)
    LOG(1, "JitGSFixup::addResetCall NYI");
#endif
}
