#include "framework/include.h"
#include "pass/regreplace.h"
#include "chunk/concrete.h"
#include "conductor/conductor.h"
#include "instr/register.h"
#include "log/registry.h"
#include "disasm/aarch64-regbits.h"

#include "chunk/dump.h"

TEST_CASE("replace x18 in libc", "[pass][full][aarch64][.]") {
#ifdef ARCH_AARCH64
    GroupRegistry::getInstance()->muteAllSettings();

    ElfMap elf(TESTDIR "stack");

    Conductor conductor;
    conductor.parseExecutable(&elf);
    conductor.parseLibraries();

    auto libc = conductor.getLibraryList()->getLibc();
    REQUIRE(libc != nullptr);

    AARCH64RegReplacePass replacer(AARCH64GPRegister::R18, 0x10);

#if 0
    // expects glibc
    auto module = libc->getElfSpace()->getModule();
    auto f = dynamic_cast<Function *>(
        CIter::named(module->getFunctionList())->find("__offtime"));

    REQUIRE(f != nullptr);
    f->accept(&replacer);

    GroupRegistry::getInstance()->applySetting("disasm", 9);

    //ChunkDumper dumper;
    //f->accept(&dumper);

    AARCH64RegBits rb;
    PhysicalRegister<AARCH64GPRegister> r18(AARCH64GPRegister::R18, true);
    for(auto block : CIter::children(f)) {
        for(auto instr : CIter::children(block)) {
            CAPTURE(instr->getAddress());
            rb.decode(instr->getSemantic()->getAssembly()->getBytes());
            CHECK(!rb.isReading(r18));
            CHECK(!rb.isWriting(r18));
        }
    }
#else
    AARCH64RegBits rb;
    PhysicalRegister<AARCH64GPRegister> r18(AARCH64GPRegister::R18, true);
    auto module = libc->getElfSpace()->getModule();
    for(auto f : CIter::functions(module)) {
        f->accept(&replacer);
        for(auto block : CIter::children(f)) {
            for(auto instr : CIter::children(block)) {
                CAPTURE(instr->getAddress());
                rb.decode(instr->getSemantic()->getAssembly()->getBytes());
                CHECK(!rb.isReading(r18));
                CHECK(!rb.isWriting(r18));
            }
        }
    }
#endif

#endif
}

