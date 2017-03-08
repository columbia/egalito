#include "framework/include.h"
#include "pass/stackextend.h"
#include "conductor/conductor.h"
#include "log/registry.h"

#ifdef ARCH_AARCH64
static size_t numberOfEpilogue(Function *f) {
    size_t n = 0;
    for(auto b : f->getChildren()->getIterable()->iterable()) {
        for(auto i : b->getChildren()->getIterable()->iterable()) {
            if(dynamic_cast<ReturnInstruction *>(i->getSemantic())) {
                n ++;
            }
            else if(auto cfi = dynamic_cast<ControlFlowInstruction *>(
                i->getSemantic())) {

                if(cfi->getMnemonic() == std::string("b")
                   || cfi->getMnemonic().find("b.", 0) != std::string::npos) {
                    auto link = dynamic_cast<NormalLink *>(cfi->getLink());
                    if(link && dynamic_cast<Function *>(&*link->getTarget())) {
                        n ++;
                    }
                }
            }
        }
    }
    return n;
}
#endif

TEST_CASE("extend simple stack frames", "[pass][fast][aarch64]") {
#ifdef ARCH_AARCH64
    GroupRegistry::getInstance()->muteAllSettings();

    ElfMap elf(TESTDIR "stack");

    Conductor conductor;
    conductor.parse(&elf, nullptr);

    auto module = conductor.getMainSpace()->getModule();

    std::map<Function *, size_t> funcsize;
    for(auto f : module->getChildren()->getIterable()->iterable()) {
        funcsize[f] = f->getSize();
    }

    StackExtendPass extender(0x10);
    module->accept(&extender);

    SECTION("without frame") {
        // tail-call
        auto f = module->getChildren()->getNamed()->find("func");
        CAPTURE(f->getSize() - funcsize[f]);
        CHECK(f->getSize() == funcsize[f] + 4 + numberOfEpilogue(f) * 4);

        f = module->getChildren()->getNamed()->find("func1");
        CAPTURE(f->getSize() - funcsize[f]);
        CHECK(f->getSize() == funcsize[f] + 4 + numberOfEpilogue(f) * 4);
    }

    SECTION("frame with local variables") {
        auto f = module->getChildren()->getNamed()->find("func2");
        CAPTURE(f->getSize() - funcsize[f]);
        CHECK(f->getSize() == funcsize[f] + 4 + 4 + numberOfEpilogue(f) * 4);
    }

    SECTION("frame with alloca") {
        auto f = module->getChildren()->getNamed()->find("funcA");
        CAPTURE(f->getSize() - funcsize[f]);
        CHECK(f->getSize() == funcsize[f] + 4 + 4 + 4 + numberOfEpilogue(f) * 4);
    }

    SECTION("no frame but stack arguments") {
        auto f = module->getChildren()->getNamed()->find("func_");
        CAPTURE(f->getSize() - funcsize[f]);
        CHECK(f->getSize() == funcsize[f] + 4 + numberOfEpilogue(f) * 4);
    }

    SECTION("frame with stack arguments") {
        auto f = module->getChildren()->getNamed()->find("func__");
        CAPTURE(f->getSize() - funcsize[f]);
        CHECK(f->getSize() == funcsize[f] + 4 + 4 + 4 + numberOfEpilogue(f) * 4);
    }

    SECTION("frames not to be changed") {
        auto f = module->getChildren()->getNamed()->find("func___");
        CAPTURE(f->getSize() - funcsize[f]);
        CHECK(f->getSize() == funcsize[f]);

        f = module->getChildren()->getNamed()->find("funcB");
        CAPTURE(f->getSize() - funcsize[f]);
        CHECK(f->getSize() == funcsize[f]);

        f = module->getChildren()->getNamed()->find("func3");
        CAPTURE(f->getSize() - funcsize[f]);
        CHECK(f->getSize() == funcsize[f]);

        f = module->getChildren()->getNamed()->find("main");
        CAPTURE(f->getSize() - funcsize[f]);
        CHECK(f->getSize() == funcsize[f]);
    }
#endif
}

