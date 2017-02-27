#include <iostream>
#include "jumptable.h"
#include "analysis/jumptable.h"
#include "conductor/conductor.h"
#include "log/registry.h"

void JumpTableIntegration::run() {
    GroupRegistry::getInstance()->muteAllSettings();
    //GroupRegistry::getInstance()->applySetting("disasm", 9);
    //GroupRegistry::getInstance()->applySetting("analysis", 9);

    try {
        ElfMap elf(TESTDIR "jumptable");

        Conductor conductor;
        conductor.parse(&elf, nullptr);

        auto module = conductor.getMainSpace()->getModule();
        auto f = module->getChildren()->getNamed()->find("main");
        if(testFunction(f, 1)) {
            std::cout << "TEST PASSED: found jump table in main\n";
        }
    }
    catch(const char *error) {
        std::cout << "TEST FAILED: error: " << error << std::endl;
    }
}

void JumpTableIntegration::run2() {
    GroupRegistry::getInstance()->muteAllSettings();
    //GroupRegistry::getInstance()->applySetting("disasm", 9);
    //GroupRegistry::getInstance()->applySetting("analysis", 9);

    try {
        ElfMap elf(TESTDIR "jumptable");

        Conductor conductor;
        conductor.parseRecursive(&elf);

        auto libc = conductor.getLibraryList()->getLibc();
        if(!libc) {
            std::cout << "TEST FAILED: can't locate libc.so in depends\n";
            return;
        }

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
                if(!testFunction(f, testCase[i].expected)) return;
            }
        }

        std::cout << "TEST PASSED: found test jump tables in libc\n";
    }
    catch(const char *error) {
        std::cout << "TEST FAILED: error: " << error << std::endl;
    }
}

bool JumpTableIntegration::testFunction(Function *f, int expected) {
    JumpTableSearch jt;
    jt.search(f);
    
    if((int)jt.getTableList().size() != expected) {
        std::cout << "TEST FAILED: function ["
            << f->getSymbol()->getName() << "]: expected " << expected
            << " jump tables but found "
            << jt.getTableList().size() << std::endl;
        return false;
    }

    auto tableList = jt.getTableList();
    for(auto table : tableList) {
        std::cout << "found jump table in ["
            << f->getSymbol()->getName() << "] at "
            << std::hex << table->getAddress() << " with "
            << std::dec << table->getEntries()
            << " entries.\n";
    }

    return true;
}
