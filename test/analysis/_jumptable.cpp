#include <sstream>
#include "config.h"
#include "framework/include.h"
#include "analysis/jumptable.h"
#include "analysis/jumptabledetection.h"
#include "conductor/conductor.h"
#include "log/registry.h"

TEST_CASE("find simple jump table in main", "[analysis][fast]") {
    GroupRegistry::getInstance()->muteAllSettings();
    //GroupRegistry::getInstance()->applySetting("disasm", 9);
    //GroupRegistry::getInstance()->applySetting("analysis", 12);
    //GroupRegistry::getInstance()->applySetting("djumptable", 9);

    ElfMap elf(TESTDIR "jumptable");

    Conductor conductor;
    conductor.parseExecutable(&elf);

    auto module = conductor.getProgram()->getMain();
    auto f = CIter::named(module->getFunctionList())->find("main");

    JumptableDetection jt(module);
    jt.detect(f);

    int jumpTableCount = (int)jt.getTableList().size();
    CAPTURE(jumpTableCount);
    REQUIRE(jumpTableCount == ANALYSIS_JUMPTABLE_MAIN_COUNT);
}

static void testFunction(Module *module, Function *f, int expected) {
    JumptableDetection jt(module);
    jt.detect(f);

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
    //GroupRegistry::getInstance()->applySetting("analysis", 12);
    //GroupRegistry::getInstance()->applySetting("djumptable", 9);

    ElfMap elf(TESTDIR "jumptable");

    Conductor conductor;
    conductor.parseExecutable(&elf);
    conductor.parseLibraries();

    auto module = conductor.getProgram()->getLibc();
    INFO("looking for libc.so in depends...");
    REQUIRE(module != nullptr);

    struct {
        const char *name;
        int expected;
    } testCase[] = {
        {"parse_expression", ANALYSIS_JUMPTABLE_PARSE_EXPRESSION_COUNT},
        {"trecurse", 0}  // this has a tail-recursive call
    };
    for(size_t i = 0; i < sizeof(testCase)/sizeof(*testCase); i ++) {
        auto name = testCase[i].name;
        auto f = CIter::named(module->getFunctionList())->find(name);
        if(f) {
            testFunction(module, f, testCase[i].expected);
        }
    }
}

static bool missingBounds(Module *module, Function *f) {
    JumptableDetection jt(module);
    jt.detect(f);
    bool missing = false;

    auto tableList = jt.getTableList();
    std::ostringstream stream;
    if(tableList.size() == 0) {
        stream << "no jump table in ["
            << f->getSymbol()->getName() << "]\n";
    }
    for(auto table : tableList) {
        stream << "found jump table in ["
            << f->getSymbol()->getName() << "] at 0x"
            << std::hex << table->getAddress() << " with "
            << std::dec << table->getEntries()
            << " entries.\n";
        if(table->getEntries() == -1) missing = true;
    }
    WARN(stream.str());
    return missing;
}

TEST_CASE("check completeness of jump tables in libc", "[analysis][full][.]") {
    GroupRegistry::getInstance()->muteAllSettings();
    //GroupRegistry::getInstance()->applySetting("disasm", 9);
    //GroupRegistry::getInstance()->applySetting("analysis", 9);

    ElfMap elf(TESTDIR "jumptable");

    Conductor conductor;
    conductor.parseExecutable(&elf);
    conductor.parseLibraries();

    auto module = conductor.getProgram()->getLibc();
    INFO("looking for libc.so in depends...");
    REQUIRE(module != nullptr);

#if 1
    std::vector<Function *> partial;
    for(auto f : CIter::functions(module)) {
        if(missingBounds(module, f)) {
            partial.push_back(f);
        }
    }
    CHECK(partial.size() == 0);

#else
    std::vector<Function *> partial;
    partial.push_back(module->getChildren()->getNamed()->find("getifaddrs_internal"));
#endif

#if 0
    if(partial.size() > 0) {
        GroupRegistry::getInstance()->applySetting("analysis", 9);
        WARN("re-doing " << partial.size() << " tests\n");
        for(auto f : partial) {
            WARN("re-doing: " << f->getSymbol()->getName());
            missingBounds(module, f);
        }
    }
#endif
}
