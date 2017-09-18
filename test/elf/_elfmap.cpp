#include "framework/include.h"
#include "elf/elfmap.h"

TEST_CASE("Elf Parser Dynamic", "[elf][dyn]") {
    ElfMap elf(TESTDIR "hello");
    CHECK(elf.isDynamic());
}

TEST_CASE("Elf Parser Executable", "[elf][exec]") {
#ifdef ARCH_X86_64
    // static PIE on AARCH64 is a shared object
    ElfMap elf(TESTDIR "hello-static");
    CHECK(elf.isExecutable());
#endif
}
