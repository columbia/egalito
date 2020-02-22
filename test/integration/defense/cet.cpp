#include "framework/include.h"
#include "conductor/interface.h"
#include "pass/endbradd.h"
#include "pass/endbrenforce.h"
#include "operation/find2.h"

#ifdef ARCH_X86_64
static void checkEndbr(Program *program, const char *functionName, bool isExpected) {
    INFO("checking for endbr in [" << functionName << "]");
    auto func = ChunkFind2(program).findFunction(functionName);
    CHECK(func != nullptr);
    if(!func) return;

    auto block1 = func->getChildren()->getIterable()->get(0);
    auto instr1 = block1->getChildren()->getIterable()->get(0);
    auto a = instr1->getSemantic()->getAssembly();

    std::vector<unsigned char> actual(
        a->getBytes(), a->getBytes() + a->getSize());
    auto expected = std::vector<unsigned char>({ 0xf3, 0x0f, 0x1e, 0xfa });
    if(isExpected) {
        CHECK(actual == expected);
    } else {
        CHECK(actual != expected);
    }
}

TEST_CASE("Control-Flow Integrity", "[cet]") {
    EgalitoInterface egalito(false, false);
    egalito.initializeParsing();
    REQUIRE(egalito.parse(TESTDIR "hello", false) != nullptr);

    auto program = egalito.getProgram();

    EndbrAddPass endbradd;
    program->accept(&endbradd);

    EndbrEnforcePass endbrEnforce;
    program->accept(&endbrEnforce);

    checkEndbr(program, "main", true);
    checkEndbr(program, "_init", true);
    checkEndbr(program, "egalito_endbr_violation", false);
    checkEndbr(program, "register_tm_clones", false);
}
#endif
