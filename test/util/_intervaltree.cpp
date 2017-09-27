#include <algorithm>  // for std::sort
#include "framework/include.h"
#include "util/intervaltree.h"

TEST_CASE("Interval tree add nodes then iterate", "[util][fast]") {
    IntervalTree tree(Range(0, 100));

    tree.add(Range(10, 2));
    tree.add(Range(20, 3));
    tree.add(Range(30, 4));

    std::vector<address_t> starts;
    std::vector<size_t> sizes;
    tree.getRoot()->inStartOrderTraversal([&] (const Range &r) {
        starts.push_back(r.getStart());
        sizes.push_back(r.getSize());
    });

    CHECK(starts == std::vector<address_t>({ 10, 20, 30 }));
    CHECK(sizes == std::vector<size_t>({ 2, 3, 4 }));
}

TEST_CASE("Interval tree lower bound", "[util][fast]") {
    IntervalTree tree(Range(0, 0x40));

    tree.add(Range(0x10, 0xe));
    tree.add(Range(0x20, 0xe));
    tree.add(Range(0x30, 0xe));

    Range output(0, 0);
    CHECK(!tree.findLowerBound(0x15, &output));

    REQUIRE(tree.findLowerBound(0x1f, &output));
    CHECK(output == Range(0x10, 0xe));

    REQUIRE(tree.findLowerBound(0x20, &output));
    CHECK(output == Range(0x10, 0xe));

    REQUIRE(tree.findLowerBound(0x23, &output));
    CHECK(output == Range(0x10, 0xe));

    REQUIRE(tree.findLowerBound(0x2e, &output));
    CHECK(output == Range(0x20, 0xe));

    REQUIRE(tree.findLowerBound(0x3e, &output));
    CHECK(output == Range(0x30, 0xe));

    REQUIRE(tree.findLowerBound(0x40, &output));
    CHECK(output == Range(0x30, 0xe));
}

TEST_CASE("Interval tree lower bound on large input", "[util][fast]") {
    IntervalTree tree(Range(0, 0x1000));

    for(int i = 0; i < 0x1000; i += 0x10) {
        tree.add(Range(i, 0x8));
    }

    Range output(0, 0);
    REQUIRE(tree.findLowerBound(0x20, &output));
    CHECK(output == Range(0x10, 0x8));

    REQUIRE(tree.findLowerBound(0x500, &output));
    CHECK(output == Range(0x500-0x10, 0x8));

    REQUIRE(tree.findLowerBound(0x200, &output));
    CHECK(output == Range(0x200-0x10, 0x8));

    REQUIRE(tree.findLowerBound(0x207, &output));
    CHECK(output == Range(0x200-0x10, 0x8));

    REQUIRE(tree.findLowerBound(0x208, &output));
    CHECK(output == Range(0x200, 0x8));

    REQUIRE(tree.findLowerBound(557, &output));
    CHECK(output == Range(544, 0x8));
}

TEST_CASE("Interval tree upper bound", "[util][fast]") {
    IntervalTree tree(Range(0, 0x40));

    tree.add(Range(0x10, 0xe));
    tree.add(Range(0x20, 0xe));
    tree.add(Range(0x30, 0xe));

    Range output(0, 0);
    REQUIRE(tree.findUpperBound(0x1, &output));
    CHECK(output == Range(0x10, 0xe));

    REQUIRE(tree.findUpperBound(0xf, &output));
    CHECK(output == Range(0x10, 0xe));

    REQUIRE(tree.findUpperBound(0x10, &output));
    CHECK(output == Range(0x20, 0xe));

    CHECK(!tree.findUpperBound(0x30, &output));
}

TEST_CASE("Interval tree find overlapping with point", "[util][fast]") {
    IntervalTree tree(Range(0, 0x40));

    tree.add(Range(0x10, 0xe));
    tree.add(Range(0x20, 0xe));
    tree.add(Range(0x30, 0x2));
    tree.add(Range(0x30, 0x3));
    tree.add(Range(0x30, 0x4));

    CHECK(tree.findOverlapping(0x10)
        == std::vector<Range>({ Range(0x10, 0xe) }));

    CHECK(tree.findOverlapping(0x1d)
        == std::vector<Range>({ Range(0x10, 0xe) }));

    CHECK(tree.findOverlapping(0x1e)
        == std::vector<Range>({ }));

    CHECK(tree.findOverlapping(0x2f)
        == std::vector<Range>({ }));

    std::vector<Range> output;
    output = tree.findOverlapping(0x31);
    std::sort(output.begin(), output.end());
    CHECK(output == std::vector<Range>(
        { Range(0x30, 0x2), Range(0x30, 0x3), Range(0x30, 0x4) }));

    output = tree.findOverlapping(0x32);
    std::sort(output.begin(), output.end());
    CHECK(output == std::vector<Range>(
        { Range(0x30, 0x3), Range(0x30, 0x4) }));

    output = tree.findOverlapping(0x33);
    std::sort(output.begin(), output.end());
    CHECK(output == std::vector<Range>(
        { Range(0x30, 0x4) }));
}
