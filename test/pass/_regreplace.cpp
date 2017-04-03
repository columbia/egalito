#include "framework/include.h"
#include "pass/regreplace.h"
#include "conductor/conductor.h"
#include "log/registry.h"

TEST_CASE("replace x18 in libc", "[pass][full][aarch64][.]") {
#ifdef ARCH_AARCH64
    ElfMap elf(TESTDIR "stack");

    Conductor conductor;
    conductor.parseExecutable(&elf);
    conductor.parseLibraries();

    auto libc = conductor.getLibraryList()->getLibc();
    INFO("looking for libc.so in depends...");
    REQUIRE(libc != nullptr);

    AARCH64RegReplacePass replacer(AARCH64GPRegister::R18, 0x10);

#if 0
    // expects glibc
    auto module = libc->getElfSpace()->getModule();
    auto f = module->getChildren()->getNamed()->find("__offtime");
    REQUIRE(f != nullptr);
    f->accept(&replacer);
#else
    auto module = libc->getElfSpace()->getModule();
    for(auto f : module->getChildren()->getIterable()->iterable()) {
        f->accept(&replacer);
    }
#endif

#endif
}

