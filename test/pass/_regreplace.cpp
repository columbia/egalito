#include <capstone/arm64.h>
#include "framework/include.h"
#include "pass/regreplace.h"
#include "conductor/conductor.h"
#include "log/registry.h"

TEST_CASE("replace x18 in libc", "[pass][full][aarch64][.]") {
#ifdef ARCH_AARCH64
    ElfMap elf(TESTDIR "stack");

    Conductor conductor;
    conductor.parseRecursive(&elf);

    auto libc = conductor.getLibraryList()->getLibc();
    INFO("looking for libc.so in depends...");
    REQUIRE(libc != nullptr);

    // expects glibc
    auto module = libc->getElfSpace()->getModule();
    auto f = module->getChildren()->getNamed()->find("__offtime");
    REQUIRE(f != nullptr);

    AARCH64RegReplacePass replacer(AARCH64GPRegister::R18, 0x10);
    f->accept(&replacer);
#endif
}

