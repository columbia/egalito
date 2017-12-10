#include <cstring>
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
        auto sandbox = egalito_conductor_setup->getSandbox();
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

    ManageGS::setEntry(egalito_gsTable, index, target->getAddress());
    return offset;
}

extern "C"
void egalito_jit_gs_reset(void) {
    egalito_printf("resetting...\n");
    //ManageGS::resetEntries(egalito_gsTable, egalito_gsCallback);
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

    addResetCall();
}

void JitGSFixup::addResetCall() {
    auto lib = conductor->getLibraryList()->get("(egalito)");
    if(!lib) throw "JitGSFixup requires libegalito.so to be transformed";

    // this can only be hooked around function call or system call
    // as it assumes that r11 is clobberable.
    auto reset = ChunkFind2(conductor).findFunctionInModule(
        "egalito_hook_jit_reset_on_syscall", lib->getElfSpace()->getModule());
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

#ifdef ARCH_X86_64
    Block *block = nullptr;
    Instruction *instr = nullptr;
    bool next = false;
    for(auto b : CIter::children(write)) {
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
