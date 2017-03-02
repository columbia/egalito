#include "framework/include.h"
#include "framework/StreamAsString.h"
#include "chunk/position.h"
#include "chunk/mutator.h"
#include "pass/chunkpass.h"
#include "conductor/conductor.h"
#include "log/registry.h"

class CheckAddressIntegrity : public ChunkPass {
private:
    address_t computed;
public:
    CheckAddressIntegrity() : computed(0) {}

    void visit(Function *function) {
        computed = function->getAddress();
        recurse(function);
    }

    void visit(Instruction *instruction) {
        CHECK(computed == instruction->getAddress());
        computed += instruction->getSize();
    }
};

TEST_CASE("position validation for simple main with default Position type") {
    GroupRegistry::getInstance()->muteAllSettings();

    delete PositionFactory::getInstance();
    PositionFactory::setInstance(nullptr);

    ElfMap elf(TESTDIR "hi0");

    Conductor conductor;
    conductor.parse(&elf, nullptr);

    auto module = conductor.getMainSpace()->getModule();
    auto func = module->getChildren()->getNamed()->find("main");

    SECTION("position validation immediately after disassembly") {
        CheckAddressIntegrity pass;
        func->accept(&pass);
    }

    SECTION("position validation after setting address to 0x4000000") {
        ChunkMutator(func).setPosition(0x4000000);

        CheckAddressIntegrity pass;
        func->accept(&pass);
    }
}

TEST_CASE("position validation for simple main over each Position type") {
    GroupRegistry::getInstance()->muteAllSettings();

    static const struct {
        PositionFactory::Mode mode;
        const char *name;
    } mode[] = {
        {PositionFactory::MODE_GENERATION_OFFSET,       "GenerationalOffsetPosition"},
        {PositionFactory::MODE_GENERATION_SUBSEQUENT,   "GenerationalSubsequentPosition"},
        {PositionFactory::MODE_CACHED_OFFSET,           "CachedOffsetPosition"},
        {PositionFactory::MODE_CACHED_SUBSEQUENT,       "CachedSubsequentPosition"},
        {PositionFactory::MODE_OFFSET,                  "OffsetPosition"},
        {PositionFactory::MODE_SUBSEQUENT,              "SubsequentPosition"}
    };

    for(size_t m = 0; m < sizeof(mode)/sizeof(*mode); m ++) {
        auto testCase = mode[m];
        SECTION(StreamAsString() << "for PositionFactory mode "
            << testCase.mode << " (" << testCase.name << ")") {

            delete PositionFactory::getInstance();
            PositionFactory::setInstance(new PositionFactory(testCase.mode));

            ElfMap elf(TESTDIR "hi0");

            Conductor conductor;
            conductor.parse(&elf, nullptr);

            auto module = conductor.getMainSpace()->getModule();
            auto func = module->getChildren()->getNamed()->find("main");

            SECTION("position validation immediately after disassembly") {
                CheckAddressIntegrity pass;
                func->accept(&pass);
            }

            SECTION("position validation after setting address to 0x4000000") {
                ChunkMutator(func).setPosition(0x4000000);

                CheckAddressIntegrity pass;
                func->accept(&pass);
            }
        }
    }
}
