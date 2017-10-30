#include "framework/include.h"
#include "analysis/walker.h"
#include "analysis/controlflow.h"
#include "conductor/conductor.h"
#include "log/registry.h"

#define DEBUG_GROUP analysis
#include "log/log.h"

TEST_CASE("CFG walker", "[analysis][fast][.]") {
    GroupRegistry::getInstance()->muteAllSettings();
    //GroupRegistry::getInstance()->applySetting("analysis", 10);

    ElfMap elf(TESTDIR "cfg");

    Conductor conductor;
    conductor.parseExecutable(&elf);

    auto module = conductor.getMainSpace()->getModule();
    auto f = CIter::named(module->getFunctionList())->find("main");

    REQUIRE(f != nullptr);
    ControlFlowGraph cfg(f);
    //cfg.dumpDot();

    // 0->1->2->3<->4->5
    // |  |
    // |  v
    // +->6
    //cfg.dump();

    SECTION("preorder") {
        Preorder order(&cfg);
        order.gen(0);
        CHECK(order.get()[0].size() == cfg.getCount());
        LOG(1, "preorder:");
        for(auto i : order.get()[0]) {
            LOG0(1, " " << i);
        }
        LOG(1, "");
    }

    SECTION("postorder") {
        Postorder order(&cfg);
        order.gen(0);
        CHECK(order.get()[0].size() == cfg.getCount());
        LOG(1, "postorder:");
        for(auto i : order.get()[0]) {
            LOG0(1, " " << i);
        }
        LOG(1, "");
    }

    SECTION("reverse postorder") {
        ReversePostorder order(&cfg);
        order.gen(0);
        CHECK(order.get()[0].size() == cfg.getCount());
        LOG(1, "reverse postorder:");
        for(auto i : order.get()[0]) {
            LOG0(1, " " << i);
        }
        LOG(1, "");
    }

    SECTION("reverse postorder reverse CFG") {
        ReverseReversePostorder order(&cfg);
        order.gen(6);
        LOG(1, "reverse postorder reverse CFG (from 6):");
        for(auto i : order.get()[0]) {
            LOG0(1, " " << i);
        }
        LOG(1, "");
        order.gen(5);
        LOG(1, "reverse postorder reverse CFG (from 5):");
        for(auto i : order.get()[0]) {
            LOG0(1, " " << i);
        }
        LOG(1, "");
    }

    SECTION("scc") {
        SccOrder order(&cfg);
        order.gen(0);
        LOG(1, "reverse postorder of SCCs:");
        LOG0(1, "{ ");
        for(auto scc :  order.get()) {
            LOG0(1, "{");
            for(auto i : scc) {
                LOG0(1, " " << i);
            }
            LOG0(1, " }");
        }
        LOG(1, " }");
        CHECK(order.get().size() == cfg.getCount() - 1);
        CHECK(order.get()[3][0] == 3);
        CHECK(order.get()[3][1] == 4);
    }

    SECTION("scc on RCFG") {
        ReverseSccOrder order(&cfg);
        order.gen(5);
        LOG(1, "reverse postorder of SCCs on RCFG:");
        LOG0(1, "{ ");
        for(auto scc :  order.get()) {
            LOG0(1, "{");
            for(auto i : scc) {
                LOG0(1, " " << i);
            }
            LOG0(1, " }");
        }
        LOG(1, " }");
        CHECK(order.get().size() == cfg.getCount() - 2);
        CHECK(order.get()[1][0] == 4);
        CHECK(order.get()[1][1] == 3);
    }
}
