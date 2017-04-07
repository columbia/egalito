#include <climits>
#include "framework/include.h"
#include "pass/promotejumps.h"

TEST_CASE("jump displacement fits-in range test", "[pass][fast][x86_64]") {
#ifdef ARCH_X86_64
    CHECK(sizeof(address_t) == 8);

    CHECK(PromoteJumpsPass::fitsIn<signed char>(1));
    CHECK(PromoteJumpsPass::fitsIn<signed char>(-1));
    CHECK(PromoteJumpsPass::fitsIn<signed char>(CHAR_MAX));
    CHECK(PromoteJumpsPass::fitsIn<signed char>(CHAR_MIN));
    CHECK(!PromoteJumpsPass::fitsIn<signed char>(CHAR_MAX+1));
    CHECK(!PromoteJumpsPass::fitsIn<signed char>(CHAR_MIN-1));

    CHECK(PromoteJumpsPass::fitsIn<signed int>(1000));
    CHECK(PromoteJumpsPass::fitsIn<signed int>(-1000));
    CHECK(PromoteJumpsPass::fitsIn<signed int>(INT_MAX));
    CHECK(PromoteJumpsPass::fitsIn<signed int>(INT_MIN));
    CHECK(!PromoteJumpsPass::fitsIn<signed int>(INT_MAX+1L));
    CHECK(!PromoteJumpsPass::fitsIn<signed int>(INT_MIN-1L));

    CHECK(PromoteJumpsPass::fitsIn<signed long>(LONG_MAX));
    CHECK(PromoteJumpsPass::fitsIn<signed long>(LONG_MIN));
    CHECK(PromoteJumpsPass::fitsIn<signed long>(ULONG_MAX));
#endif
}
