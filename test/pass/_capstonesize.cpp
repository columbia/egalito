#include "framework/include.h"
#include "pass/capstonesize.h"
#include "conductor/conductor.h"
#include "log/registry.h"

TEST_CASE("calculate memory used by capstone data structures", "[.][pass]") {
    GroupRegistry::getInstance()->muteAllSettings();

    ElfMap elf(TESTDIR "hello");

    Conductor conductor;
    conductor.parseRecursive(&elf);

    CapstoneSizePass pass;

    SECTION("hello only") {
        auto module = conductor.getMainSpace()->getModule();

        module->accept(&pass);
        WARN("size: " << pass.getSize());
        WARN("count: " << pass.getCount());
        WARN("raw size: " << pass.getRawSize());
    }

    SECTION("libc only") {
        auto libc = conductor.getLibraryList()->getLibc();

        libc->getElfSpace()->getModule()->accept(&pass);
        WARN("size: " << pass.getSize());
        WARN("count: " << pass.getCount());
        WARN("raw size: " << pass.getRawSize());
    }
}
