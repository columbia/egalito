#include "framework/include.h"
#include "framework/StreamAsString.h"
#include "chunk/position.h"
#include "chunk/instruction.h"
#include "chunk/mutator.h"
#include "chunk/dump.h"
#include "disasm/disassemble.h"
#include "pass/chunkpass.h"
#include "conductor/conductor.h"
#include "log/registry.h"

static Instruction *makeBreakInstr() {
#ifdef ARCH_X86_64
    std::vector<unsigned char> bytes = {0xcc};  // hlt
#else
    #error "not ported to ARM yet"
#endif
    return Disassemble::instruction(bytes, true, 0);
}

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

TEST_CASE("position validation for simple main with default Position type", "[chunk][fast]") {
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

TEST_CASE("position validation for simple main over each Position type", "[chunk][normal]") {
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

            SECTION("position validation after inserting instruction") {
                auto breakInstr = makeBreakInstr();
                auto firstBlock = func->getChildren()->getIterable()->get(0);
                auto firstInstr = firstBlock->getChildren()->getIterable()->get(0);

                PositionFactory *positionFactory = PositionFactory::getInstance();
                breakInstr->setPosition(positionFactory->makePosition(
                    firstInstr, breakInstr, firstInstr->getSize()));

                ChunkMutator(firstBlock).insertAfter(firstInstr, breakInstr);

                ChunkDumper dumper;
                func->accept(&dumper);

                CheckAddressIntegrity pass;
                func->accept(&pass);
            }
        }
    }
}
