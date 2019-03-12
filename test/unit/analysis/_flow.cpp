#include "framework/include.h"
#include "analysis/flow.h"
#include "analysis/slicing.h"
#include "instr/memory.h"

TEST_CASE("Backward Flow", "[analysis][flow][fast]") {
    DirectedSearchState<BackwardFlow> state(nullptr, nullptr);

    auto reg1 = FlowRegElement(Register(1), &state);
    auto reg2 = FlowRegElement(Register(2), &state);
    auto reg3 = FlowRegElement(Register(3), &state);

    SECTION("channel w/o interest (overwriteTarget)") {
        BackwardFlow::channel(&reg1, &reg2, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
    }

    SECTION("channel w/o interest (no overwriteTarget)") {
        BackwardFlow::channel(&reg1, &reg2, false);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
    }

    SECTION("channel w/ interest (overwriteTarget)") {
        reg1.markAsInteresting();
        BackwardFlow::channel(&reg1, &reg2, true);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);

        BackwardFlow::channel(&reg2, &reg1, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == false);
    }

    SECTION("channel w/ interest (no overwriteTarget)") {
        reg1.markAsInteresting();
        BackwardFlow::channel(&reg1, &reg2, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);

        BackwardFlow::channel(&reg2, &reg1, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == false);
    }

    SECTION("confluence(3 args) w/o interest (overwriteTarget)") {
        BackwardFlow::confluence(&reg1, &reg2, &reg3, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
    }

    SECTION("confluence(3 args) w/o interest (no overwriteTarget)") {
        BackwardFlow::confluence(&reg1, &reg2, &reg3, false);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
    }

    SECTION("confluence(3 args) w/ interest (overwriteTarget)") {
        reg1.markAsInteresting();
        BackwardFlow::confluence(&reg1, &reg2, &reg3, true);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);

        BackwardFlow::confluence(&reg2, &reg3, &reg1, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == true);
    }

    SECTION("confluence(3 args) w/ interest (no overwriteTarget)") {
        reg1.markAsInteresting();
        BackwardFlow::confluence(&reg1, &reg2, &reg3, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);

        BackwardFlow::confluence(&reg3, &reg2, &reg1, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == true);
    }

    Memory mem1(Register(REGISTER_SP), Register(1), 100);
    FlowMemElement m1(&mem1, &state);

    SECTION("confluence(1 reg, 1 mem) w/o interest (overwriteTarget)") {
        BackwardFlow::channel(&reg3, &m1, true);   // store
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getMem(100) == false);

        BackwardFlow::channel(&m1, &reg2, true);   // load
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getMem(100) == false);
    }

    SECTION("confluence(1 reg, 1 mem) w/o interest (no overwriteTarget)") {
        BackwardFlow::channel(&reg3, &m1, false);   // store
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getMem(100) == false);

        BackwardFlow::channel(&m1, &reg2, false);   // load
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getMem(100) == false);
    }

    SECTION("confluence(1 reg, 1 mem) w/ interest (overwriteTarget)") {
        reg3.markAsInteresting();
        BackwardFlow::channel(&reg3, &m1, true);   // store
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == true);
        CHECK(state.getMem(100) == false);

        reg2.markAsInteresting();
        BackwardFlow::channel(&m1, &reg2, true);   // load
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == true);
        CHECK(state.getMem(100) == true);
    }

    SECTION("confluence(1 reg, 1 mem) w/ interest (no overwriteTarget)") {
        reg3.markAsInteresting();
        BackwardFlow::channel(&reg3, &m1, false);   // store
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == true);
        CHECK(state.getMem(100) == false);

        reg2.markAsInteresting();
        BackwardFlow::channel(&m1, &reg2, false);   // load
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == true);
        CHECK(state.getMem(100) == true);
    }
}

TEST_CASE("Forward Flow", "[analysis][flow][fast]") {
    DirectedSearchState<ForwardFlow> state(nullptr, nullptr);

    auto reg1 = FlowRegElement((Register)1, &state);
    auto reg2 = FlowRegElement((Register)2, &state);
    auto reg3 = FlowRegElement((Register)3, &state);

    SECTION("channel w/o interest (overwriteTarget)") {
        ForwardFlow::channel(&reg1, &reg2, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
    }

    SECTION("channel w/o interest (no overwriteTarget)") {
        ForwardFlow::channel(&reg1, &reg2, false);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
    }

    SECTION("channel w/ interest (overwriteTarget)") {
        reg1.markAsInteresting();
        ForwardFlow::channel(&reg1, &reg2, true);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == false);

        ForwardFlow::channel(&reg3, &reg1, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == false);
    }

    SECTION("channel w/ interest (no overwriteTarget)") {
        reg1.markAsInteresting();
        ForwardFlow::channel(&reg1, &reg2, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == false);

        ForwardFlow::channel(&reg2, &reg1, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == false);
    }

    SECTION("confluence(3 args) w/o interest (overwriteTarget)") {
        ForwardFlow::confluence(&reg1, &reg2, &reg3, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
    }

    SECTION("confluence(3 args) w/o interest (no overwriteTarget)") {
        ForwardFlow::confluence(&reg1, &reg2, &reg3, false);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
    }

    SECTION("confluence(3 args) w/ interest (overwriteTarget)") {
        reg1.markAsInteresting();
        ForwardFlow::confluence(&reg1, &reg2, &reg3, true);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == true);

        reg3.forget();
        ForwardFlow::confluence(&reg2, &reg3, &reg1, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
    }

    SECTION("confluence(3 args) w/ interest (no overwriteTarget)") {
        reg1.markAsInteresting();
        ForwardFlow::confluence(&reg1, &reg2, &reg3, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == true);

        reg3.forget();
        ForwardFlow::confluence(&reg2, &reg3, &reg1, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
    }

    Memory mem1(Register(REGISTER_SP), Register(1), 100);
    FlowMemElement m1(&mem1, &state);

    SECTION("confluence(1 reg, 1 mem) w/o interest (overwriteTarget)") {
        ForwardFlow::channel(&reg3, &m1, true);     // store
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getMem(100) == false);

        ForwardFlow::channel(&m1, &reg2, true);     // load
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getMem(100) == false);
    }

    SECTION("confluence(1 reg, 1 mem) w/o interest (no overwriteTarget)") {
        ForwardFlow::channel(&reg3, &m1, false);    // store
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getMem(100) == false);

        ForwardFlow::channel(&m1, &reg2, false);    // load
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getMem(100) == false);
    }

    SECTION("confluence(1 reg, 1 mem) w/ interest (overwriteTarget)") {
        reg3.markAsInteresting();
        ForwardFlow::channel(&reg3, &m1, true);     // store
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == true);
        CHECK(state.getMem(100) == true);

        state.removeMem(100);
        reg2.markAsInteresting();
        ForwardFlow::channel(&m1, &reg2, true);     // load
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == true);
        CHECK(state.getMem(100) == false);
    }

    SECTION("confluence(1 reg, 1 mem) w/ interest (no overwriteTarget)") {
        reg3.markAsInteresting();
        ForwardFlow::channel(&reg3, &m1, false);    // store
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == true);
        CHECK(state.getMem(100) == true);

        state.removeMem(100);
        reg2.markAsInteresting();
        ForwardFlow::channel(&m1, &reg2, false);    // load
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == true);
        CHECK(state.getMem(100) == false);
    }
}
