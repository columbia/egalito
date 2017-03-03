#include <sstream>
#include "framework/include.h"
#include "analysis/jumptable.h"
#include "conductor/conductor.h"
#include "log/registry.h"

TEST_CASE("find simple jump table in main", "[analysis][fast]") {
    GroupRegistry::getInstance()->muteAllSettings();
    //GroupRegistry::getInstance()->applySetting("disasm", 9);
    //GroupRegistry::getInstance()->applySetting("analysis", 9);

    ElfMap elf(TESTDIR "jumptable");

    Conductor conductor;
    conductor.parse(&elf, nullptr);

    auto module = conductor.getMainSpace()->getModule();
    auto f = module->getChildren()->getNamed()->find("main");

    JumpTableSearch jt;
    jt.search(f);

    int jumpTableCount = (int)jt.getTableList().size();
    CAPTURE(jumpTableCount);
    REQUIRE(jumpTableCount == 1);
}

static void testFunction(Function *f, int expected) {
    JumpTableSearch jt;
    jt.search(f);

    auto tableList = jt.getTableList();
    std::ostringstream stream;
    for(auto table : tableList) {
        stream << "found jump table in ["
            << f->getSymbol()->getName() << "] at 0x"
            << std::hex << table->getAddress() << " with "
            << std::dec << table->getEntries()
            << " entries.\n";
    }
    INFO(stream.str());
    auto jumpTableCount = (int)tableList.size();
    CAPTURE(jumpTableCount);
    REQUIRE(jumpTableCount == expected);
}

TEST_CASE("find some jump tables in libc", "[analysis][full]") {
    GroupRegistry::getInstance()->muteAllSettings();
    //GroupRegistry::getInstance()->applySetting("disasm", 9);
    //GroupRegistry::getInstance()->applySetting("analysis", 9);

    ElfMap elf(TESTDIR "jumptable");

    Conductor conductor;
    conductor.parseRecursive(&elf);

    auto libc = conductor.getLibraryList()->getLibc();
    INFO("looking for libc.so in depends...");
    REQUIRE(libc != nullptr);

    auto module = libc->getElfSpace()->getModule();
    struct {
        const char *name;
        int expected;
    } testCase[] = {
        {"parse_expression", 2},
        {"trecurse", 0}  // this has a tail-recursive call
    };
    for(size_t i = 0; i < sizeof(testCase)/sizeof(*testCase); i ++) {
        auto name = testCase[i].name;
        auto f = module->getChildren()->getNamed()->find(name);
        if(f) {
            testFunction(f, testCase[i].expected);
        }
    }
}
