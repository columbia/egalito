#include "framework/include.h"
#include "analysis/flow.h"
#include "analysis/slicing.h"

TEST_CASE("Backward Flow", "[analysis][flow][fast]") {
    BackwardFlowFactory factory;
    SearchState state(nullptr, nullptr);

    auto reg1 = factory.makeFlow(1, &state);
    auto reg2 = factory.makeFlow(2, &state);
    auto reg3 = factory.makeFlow(3, &state);
    auto reg4 = factory.makeFlow(4, &state);

    SECTION("channel w/o interest (overwriteTarget)") {
        reg2->channel(reg1, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("channel w/o interest (no overwriteTarget)") {
        reg2->channel(reg1, false);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("channel w/ interest (overwriteTarget)") {
        reg1->markAsInteresting();
        reg2->channel(reg1, true);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);

        reg1->channel(reg2, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("channel w/ interest (no overwriteTarget)") {
        reg1->markAsInteresting();
        reg2->channel(reg1, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);

        reg1->channel(reg2, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(2 args) w/o interest (overwriteTarget)") {
        reg3->confluence(reg1, reg2, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(2 args) w/o interest (no overwriteTarget)") {
        reg3->confluence(reg1, reg2, false);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(2 args) w/ interest (overwriteTarget)") {
        reg1->markAsInteresting();
        reg3->confluence(reg1, reg2, true);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);

        reg1->confluence(reg2, reg3, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == true);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(2 args) w/ interest (no overwriteTarget)") {
        reg1->markAsInteresting();
        reg3->confluence(reg1, reg2, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);

        reg1->confluence(reg2, reg3, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == true);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(3 args) w/o interest (overwriteTarget)") {
        reg4->confluence(reg1, reg2, reg3, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(3 args) w/o interest (no overwriteTarget)") {
        reg4->confluence(reg1, reg2, reg3, false);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(3 args) w/ interest (overwriteTarget)") {
        reg1->markAsInteresting();
        reg4->confluence(reg1, reg2, reg3, true);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);

        reg1->confluence(reg2, reg3, reg4, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == true);
        CHECK(state.getReg(4) == true);
    }

    SECTION("confluence(3 args) w/ interest (no overwriteTarget)") {
        reg1->markAsInteresting();
        reg4->confluence(reg1, reg2, reg3, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);

        reg1->confluence(reg2, reg3, reg4, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == true);
        CHECK(state.getReg(4) == true);
    }

    delete reg1;
    delete reg2;
    delete reg3;
}

TEST_CASE("Forward Flow", "[analysis][flow][fast]") {
    ForwardFlowFactory factory;
    SearchState state(nullptr, nullptr);

    auto reg1 = factory.makeFlow(1, &state);
    auto reg2 = factory.makeFlow(2, &state);
    auto reg3 = factory.makeFlow(3, &state);
    auto reg4 = factory.makeFlow(4, &state);

    SECTION("channel w/o interest (overwriteTarget)") {
        reg2->channel(reg1, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("channel w/o interest (no overwriteTarget)") {
        reg2->channel(reg1, false);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("channel w/ interest (overwriteTarget)") {
        reg1->markAsInteresting();
        reg2->channel(reg1, true);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);

        reg1->channel(reg3, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("channel w/ interest (no overwriteTarget)") {
        reg1->markAsInteresting();
        reg2->channel(reg1, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);

        reg1->channel(reg2, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == true);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(2 args) w/o interest (overwriteTarget)") {
        reg3->confluence(reg1, reg2, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(2 args) w/o interest (no overwriteTarget)") {
        reg3->confluence(reg1, reg2, false);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(2 args) w/ interest (overwriteTarget)") {
        reg1->markAsInteresting();
        reg3->confluence(reg1, reg2, true);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == true);
        CHECK(state.getReg(4) == false);

        reg3->forget();
        reg1->confluence(reg2, reg3, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(2 args) w/ interest (no overwriteTarget)") {
        reg1->markAsInteresting();
        reg3->confluence(reg1, reg2, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == true);
        CHECK(state.getReg(4) == false);

        reg3->forget();
        reg1->confluence(reg2, reg3, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(3 args) w/o interest (overwriteTarget)") {
        reg4->confluence(reg1, reg2, reg3, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(3 args) w/o interest (no overwriteTarget)") {
        reg4->confluence(reg1, reg2, reg3, false);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(3 args) w/ interest (overwriteTarget)") {
        reg1->markAsInteresting();
        reg4->confluence(reg1, reg2, reg3, true);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == true);

        reg4->forget();
        reg1->confluence(reg2, reg3, reg4, true);
        CHECK(state.getReg(1) == false);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    SECTION("confluence(3 args) w/ interest (no overwriteTarget)") {
        reg1->markAsInteresting();
        reg4->confluence(reg1, reg2, reg3, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == true);

        reg4->forget();
        reg1->confluence(reg2, reg3, reg4, false);
        CHECK(state.getReg(1) == true);
        CHECK(state.getReg(2) == false);
        CHECK(state.getReg(3) == false);
        CHECK(state.getReg(4) == false);
    }

    delete reg1;
    delete reg2;
    delete reg3;
}
