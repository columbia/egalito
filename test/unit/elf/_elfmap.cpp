#include "framework/include.h"
#include "elf/elfmap.h"

TEST_CASE("Elf Parser Dynamic", "[elf][dyn]") {
    ElfMap elf(TESTDIR "hello");
    CHECK(elf.isDynamic());
}
