#include "framework/include.h"
#include "analysis/slicingtree.h"

TEST_CASE("TreeNodeContant canbe", "[analysis][slicingtree][fast][.]") {
    TreeNodeConstant t1(1);
    TreeNodeConstant t2(1);
    REQUIRE(t1.canbe(&t2) == true);

    TreeNodeConstant t3(2);
    REQUIRE(t1.canbe(&t3) == false);

    TreeNodeAddress t4(1);
    REQUIRE(t1.canbe(&t4) == false);
}

TEST_CASE("TreeNodeAddress canbe", "[analysis][slicingtree][fast][.]") {
    TreeNodeAddress t1(1);
    TreeNodeAddress t2(1);
    REQUIRE(t1.canbe(&t2) == true);

    TreeNodeAddress t3(2);
    REQUIRE(t1.canbe(&t3) == false);

    TreeNodeRegister t4(1);
    REQUIRE(t1.canbe(&t4) == false);
}

TEST_CASE("TreeNodeRegister canbe", "[analysis][slicingtree][fast][.]") {
    TreeNodeRegister t1(1);
    TreeNodeRegister t2(1);
    REQUIRE(t1.canbe(&t2) == true);

    TreeNodeRegister t3(2);
    REQUIRE(t1.canbe(&t3) == false);

    TreeNodeAddress t4(1);
    REQUIRE(t1.canbe(&t4) == false);
}

TEST_CASE("TreeNodeRegisterRIP canbe", "[analysis][slicingtree][fast][.]") {
    TreeNodeRegisterRIP t1(1);
    TreeNodeRegisterRIP t2(1);
    REQUIRE(t1.canbe(&t2) == true);

    TreeNodeRegisterRIP t3(2);
    REQUIRE(t1.canbe(&t3) == false);

    TreeNodeAddress t4(1);
    REQUIRE(t1.canbe(&t4) == false);
}

TEST_CASE("TreeNodeDereference canbe", "[analysis][slicingtree][fast][.]") {
    TreeNodeAddress ta(1);
    TreeNodeAddress tb(1);
    TreeNodeDereference t1(&ta, 4);
    TreeNodeDereference t2(&tb, 4);

    REQUIRE(t1.canbe(&t2) == true);

    TreeNodeAddress tc(2);
    TreeNodeDereference t3(&tc, 4);
    REQUIRE(t1.canbe(&t3) == false);

    REQUIRE(t1.canbe(&tc) == false);
}

TEST_CASE("TreeNodeJump canbe", "[analysis][slicingtree][fast][.]") {
    TreeNodeAddress ta(1);
    TreeNodeAddress tb(1);
    TreeNodeJump t1(&ta);
    TreeNodeJump t2(&tb);

    REQUIRE(t1.canbe(&t2) == true);

    TreeNodeAddress tc(2);
    TreeNodeJump t3(&tc);
    REQUIRE(t1.canbe(&t3) == false);

    REQUIRE(t1.canbe(&tc) == false);
}

TEST_CASE("TreeNodeSignExtendByte canbe", "[analysis][slicingtree][fast][.]") {
    TreeNodeAddress ta(1);
    TreeNodeAddress tb(1);
    TreeNodeSignExtendByte t1(&ta);
    TreeNodeSignExtendByte t2(&tb);

    REQUIRE(t1.canbe(&t2) == true);

    TreeNodeAddress tc(2);
    TreeNodeSignExtendByte t3(&tc);
    REQUIRE(t1.canbe(&t3) == false);

    REQUIRE(t1.canbe(&tc) == false);
}

TEST_CASE("TreeNodeSignExtendHalfWord canbe", "[analysis][slicingtree][fast][.]") {
    TreeNodeAddress ta(1);
    TreeNodeAddress tb(1);
    TreeNodeSignExtendHalfWord t1(&ta);
    TreeNodeSignExtendHalfWord t2(&tb);

    REQUIRE(t1.canbe(&t2) == true);

    TreeNodeAddress tc(2);
    TreeNodeSignExtendHalfWord t3(&tc);
    REQUIRE(t1.canbe(&t3) == false);

    REQUIRE(t1.canbe(&tc) == false);
}

TEST_CASE("TreeNodeSignExtendWord canbe", "[analysis][slicingtree][fast][.]") {
    TreeNodeAddress ta(1);
    TreeNodeAddress tb(1);
    TreeNodeSignExtendWord t1(&ta);
    TreeNodeSignExtendWord t2(&tb);

    REQUIRE(t1.canbe(&t2) == true);

    TreeNodeAddress tc(2);
    TreeNodeSignExtendWord t3(&tc);
    REQUIRE(t1.canbe(&t3) == false);

    REQUIRE(t1.canbe(&tc) == false);
}

TEST_CASE("TreeNodeUnsignedExtendWord canbe", "[analysis][slicingtree][fast][.]") {
    TreeNodeAddress ta(1);
    TreeNodeAddress tb(1);
    TreeNodeUnsignedExtendWord t1(&ta);
    TreeNodeUnsignedExtendWord t2(&tb);

    REQUIRE(t1.canbe(&t2) == true);

    TreeNodeAddress tc(2);
    TreeNodeUnsignedExtendWord t3(&tc);
    REQUIRE(t1.canbe(&t3) == false);

    REQUIRE(t1.canbe(&tc) == false);
}

TEST_CASE("TreeNodeAddition canbe", "[analysis][slicingtree][fast][.]") {
    TreeNodeAddress ta(1);
    TreeNodeAddress tb(1);
    TreeNodeAddition t1(&ta, &ta);
    TreeNodeAddition t2(&tb, &tb);

    REQUIRE(t1.canbe(&t2) == true);

    TreeNodeAddress tc(2);
    TreeNodeAddition t3(&ta, &tc);
    REQUIRE(t1.canbe(&t3) == false);

    TreeNodeAddition t4(&tc, &ta);
    REQUIRE(t1.canbe(&t3) == false);

    REQUIRE(t1.canbe(&tc) == false);
}

// skip TreeNodeSubtraction, TreeNodeMultiplication, TreeNodeLogicalShiftLeft

TEST_CASE("TreeNodeComparison canbe", "[analysis][slicingtree][fast][.]") {
    TreeNodeAddress ta(1);
    TreeNodeAddress tb(1);
    TreeNodeComparison t1(&ta, &ta);
    TreeNodeComparison t2(&tb, &tb);

    REQUIRE(t1.canbe(&t2) == true);

    TreeNodeAddress tc(2);
    TreeNodeComparison t3(&ta, &tc);
    REQUIRE(t1.canbe(&t3) == false);

    TreeNodeComparison t4(&tc, &ta);
    REQUIRE(t1.canbe(&t3) == false);

    REQUIRE(t1.canbe(&tc) == false);
}

TEST_CASE("TreeNodeMultipleParents canbe", "[analysis][slicingtree][fast][.]") {
    TreeNodeAddress ta(1);
    TreeNodeAddress tb(1);
    TreeNodeMultipleParents t1;
    TreeNodeMultipleParents t2;

    // t1: (MULTI 1 | 1)
    t1.addParent(&ta);
    t1.addParent(&tb);

    // t2: (MULTI 1 | 1)
    t2.addParent(&ta);
    t2.addParent(&tb);

    REQUIRE(t1.canbe(&t2) == true);

    TreeNodeAddress tc(2);
    REQUIRE(t1.canbe(&tc) == false);

    // loose
    // t3: (MULTI 1 | 2)
    TreeNodeMultipleParents t3;
    t3.addParent(&ta);
    t3.addParent(&tc);
    REQUIRE(t1.canbe(&t3) == true);

    // t4: (MULTI 2 | 1)
    TreeNodeMultipleParents t4;
    t4.addParent(&tc);
    t4.addParent(&ta);
    REQUIRE(t1.canbe(&t4) == true);

    // t5: (MULTI 2 | 2)
    TreeNodeMultipleParents t5;
    t5.addParent(&tc);
    t5.addParent(&tc);
    REQUIRE(t1.canbe(&t5) == false);

    // nested multiple
    // t6: (MULTI (MULTI 2 | 2) | 1)
    TreeNodeMultipleParents t6;
    t6.addParent(&t5);
    t6.addParent(&ta);
    REQUIRE(t1.canbe(&t6) == true);
    REQUIRE(t6.canbe(&t1) == true);
    REQUIRE(t6.canbe(&t2) == true);
    REQUIRE(t2.canbe(&t6) == true);

    // t7 : (MULTI 3 | 3)
    TreeNodeAddress td(3);
    TreeNodeMultipleParents t7;
    t7.addParent(&td);
    t7.addParent(&td);
    //t6.print(TreePrinter(2, 0));
    //t7.print(TreePrinter(2, 0));
    REQUIRE(t6.canbe(&t7) == false);
    REQUIRE(t7.canbe(&t6) == false);
}
