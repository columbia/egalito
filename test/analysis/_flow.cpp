#include "framework/include.h"
#include "analysis/flow.h"
#include "analysis/slicing.h"

TEST_CASE("Backward Flow", "[analysis][flow][fast]") {
    BackwardSearchState state(nullptr, nullptr);

    auto reg1 = FlowElement((Register)1, &state);
    auto reg2 = FlowElement((Register)2, &state);
    auto reg3 = FlowElement((Register)3, &state);
    auto reg4 = FlowElement((Register)4, &state);

    SECTION("channel w/o interest (overwriteTarget)") {
        BackwardFlow::channel(&reg1, &reg2, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("channel w/o interest (no overwriteTarget)") {
        BackwardFlow::channel(&reg1, &reg2, false);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("channel w/ interest (overwriteTarget)") {
        reg1.markAsInteresting();
        BackwardFlow::channel(&reg1, &reg2, true);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);

        BackwardFlow::channel(&reg2, &reg1, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("channel w/ interest (no overwriteTarget)") {
        reg1.markAsInteresting();
        BackwardFlow::channel(&reg1, &reg2, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);

        BackwardFlow::channel(&reg2, &reg1, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(2 args) w/o interest (overwriteTarget)") {
        BackwardFlow::confluence(&reg1, &reg2, &reg3, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(2 args) w/o interest (no overwriteTarget)") {
        BackwardFlow::confluence(&reg1, &reg2, &reg3, false);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(2 args) w/ interest (overwriteTarget)") {
        reg1.markAsInteresting();
        BackwardFlow::confluence(&reg1, &reg2, &reg3, true);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);

        BackwardFlow::confluence(&reg2, &reg3, &reg1, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == true);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(2 args) w/ interest (no overwriteTarget)") {
        reg1.markAsInteresting();
        BackwardFlow::confluence(&reg1, &reg2, &reg3, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);

        BackwardFlow::confluence(&reg3, &reg2, &reg1, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == true);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(3 args) w/o interest (overwriteTarget)") {
        BackwardFlow::confluence(&reg1, &reg2, &reg3, &reg4, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(3 args) w/o interest (no overwriteTarget)") {
        BackwardFlow::confluence(&reg1, &reg2, &reg3, &reg4, false);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(3 args) w/ interest (overwriteTarget)") {
        reg1.markAsInteresting();
        BackwardFlow::confluence(&reg1, &reg2, &reg3, &reg4, true);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);

        BackwardFlow::confluence(&reg2, &reg3, &reg4, &reg1, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == true);
        CHECK(state.getReg(4) == true);
    }

    SECTION("confluence(3 args) w/ interest (no overwriteTarget)") {
        reg1.markAsInteresting();
        BackwardFlow::confluence(&reg1, &reg2, &reg3, &reg4, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);

        BackwardFlow::confluence(&reg2, &reg3, &reg4, &reg1, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == true);
        CHECK(state.getReg(4) == true);
    }
}

TEST_CASE("Forward Flow", "[analysis][flow][fast]") {
    ForwardSearchState state(nullptr, nullptr);

    auto reg1 = FlowElement((Register)1, &state);
    auto reg2 = FlowElement((Register)2, &state);
    auto reg3 = FlowElement((Register)3, &state);
    auto reg4 = FlowElement((Register)4, &state);

    SECTION("channel w/o interest (overwriteTarget)") {
        ForwardFlow::channel(&reg1, &reg2, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("channel w/o interest (no overwriteTarget)") {
        ForwardFlow::channel(&reg1, &reg2, false);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("channel w/ interest (overwriteTarget)") {
        reg1.markAsInteresting();
        ForwardFlow::channel(&reg1, &reg2, true);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);

        ForwardFlow::channel(&reg3, &reg1, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("channel w/ interest (no overwriteTarget)") {
        reg1.markAsInteresting();
        ForwardFlow::channel(&reg1, &reg2, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);

        ForwardFlow::channel(&reg2, &reg1, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(2 args) w/o interest (overwriteTarget)") {
        ForwardFlow::confluence(&reg1, &reg2, &reg3, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(2 args) w/o interest (no overwriteTarget)") {
        ForwardFlow::confluence(&reg1, &reg2, &reg3, false);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(2 args) w/ interest (overwriteTarget)") {
        reg1.markAsInteresting();
        ForwardFlow::confluence(&reg1, &reg2, &reg3, true);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == true);
        CHECK(state.getReg(4) == false);

        reg3.forget();
        ForwardFlow::confluence(&reg2, &reg3, &reg1, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(2 args) w/ interest (no overwriteTarget)") {
        reg1.markAsInteresting();
        ForwardFlow::confluence(&reg1, &reg2, &reg3, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == true);
        CHECK(state.getReg(4) == false);

        reg3.forget();
        ForwardFlow::confluence(&reg2, &reg3, &reg1, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(3 args) w/o interest (overwriteTarget)") {
        ForwardFlow::confluence(&reg1, &reg2, &reg3, &reg4, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(3 args) w/o interest (no overwriteTarget)") {
        ForwardFlow::confluence(&reg1, &reg2, &reg3, &reg4, false);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(3 args) w/ interest (overwriteTarget)") {
        reg1.markAsInteresting();
        ForwardFlow::confluence(&reg1, &reg2, &reg3, &reg4, true);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == true);

        reg4.forget();
        ForwardFlow::confluence(&reg2, &reg3, &reg4, &reg1, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(3 args) w/ interest (no overwriteTarget)") {
        reg1.markAsInteresting();
        ForwardFlow::confluence(&reg1, &reg2, &reg3, &reg4, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == true);

        reg4.forget();
        ForwardFlow::confluence(&reg2, &reg3, &reg4, &reg1, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }
}
