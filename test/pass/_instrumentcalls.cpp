#include "framework/include.h"
#include "pass/instrumentcalls.h"
#include "pass/switchcontext.h"
#include "conductor/conductor.h"

#include "log/temp.h"
#include "chunk/dump.h"

#ifdef ARCH_AARCH64
static int checkFunction(Function *function, Function *entry, Function *exit) {
    int call_count = 0;
    for(auto block : function->getChildren()->getIterable()->iterable()) {
        for(auto ins : block->getChildren()->getIterable()->iterable()) {
            auto semantic = ins->getSemantic();
            if(auto cfi = dynamic_cast<ControlFlowInstruction *>(semantic)) {
                auto target = cfi->getLink()->getTarget();
                if(target == entry) {
                    call_count++;
                }
                else if(target == exit) {
                    call_count++;
                }
            }
        }
    }
    return call_count;
}
#endif

TEST_CASE("instrument a function", "[pass][fast][aarch64]") {
#ifdef ARCH_AARCH64
    ElfMap elf(TESTDIR "log");

    Conductor conductor;
    conductor.parseExecutable(&elf);

    auto module = conductor.getMainSpace()->getModule();
    auto entry = CIter::named(module->getFunctionList())->find("entryAdvice");
    auto exit = CIter::named(module->getFunctionList())->find("exitAdvice");

    REQUIRE(entry != nullptr);
    REQUIRE(exit != nullptr);

    SwitchContextPass switcher;
    entry->accept(&switcher);
    exit->accept(&switcher);

    InstrumentCallsPass instrumenter;
    instrumenter.setEntryAdvice(entry);
    instrumenter.setExitAdvice(exit);
    instrumenter.setPredicate([](Function *function) {
        return (function->getName() == "main"); });
    module->accept(&instrumenter);

#if 0
    TemporaryLogLevel tll("chunk", 5);
    TemporaryLogLevel tll2("disasm", 10);
    ChunkDumper dumper;
    module->accept(&dumper);
#endif

    struct {
        const char *name;
        int expected;
    } testCase[] = {
        {"main", 2},
        {"__libc_csu_init", 0}
    };
    for(size_t i = 0; i < sizeof(testCase)/sizeof(*testCase); i ++) {
        auto name = testCase[i].name;
        auto f = CIter::named(module->getFunctionList())->find(name);
        REQUIRE(f != nullptr);
        CHECK(checkFunction(f, entry, exit) == testCase[i].expected);
    }
#endif
}

