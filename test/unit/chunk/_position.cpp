#include "framework/include.h"
#include "StreamAsString.h"
#include "chunk/position.h"
#include "chunk/dump.h"
#include "operation/mutator.h"
#include "instr/concrete.h"
#include "disasm/disassemble.h"
#include "pass/chunkpass.h"
#include "conductor/conductor.h"
#include "log/registry.h"

static Instruction *makeBreakInstr() {
#ifdef ARCH_X86_64
    std::vector<unsigned char> bytes = {0xcc};  // hlt
#else
    std::vector<unsigned char> bytes = {0x00, 0x00, 0x40, 0xd4}; //hlt #0
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

#define NONE static_cast<size_t>(-1)

// Makes sure next, prev, and parent pointers are correct.
// This is a very thorough test but it involves a lot of assertions.
class CheckPrevNextIntegrity : public ChunkPass {
private:
    Function *function;
    Block *block;
public:
    CheckPrevNextIntegrity() : function(nullptr), block(nullptr) {}
    void visit(Function *function) {
        this->function = function;
        recurse(function);
    }
    void visit(Block *block) {
        if(function) CHECK(block->getParent() == function);
        this->block = block;
        recurse(block);
    }

    void visit(Instruction *instruction) {
        CAPTURE(instruction->getName());

        CHECK(instruction->getParent() == block);
        auto here = block->getChildren()->getIterable()->indexOf(instruction);
        REQUIRE(here != NONE);
        auto prev = static_cast<Instruction *>(instruction->getPreviousSibling());
        auto next = static_cast<Instruction *>(instruction->getNextSibling());

        auto count = block->getChildren()->getIterable()->getCount();
        if(here > 0) CHECK(prev != nullptr);
        if(here + 1 < count) CHECK(next != nullptr);

        auto prevIndex = NONE;
        auto nextIndex = NONE;
        if(prev) prevIndex = block->getChildren()->getIterable()->indexOf(prev);
        if(next) nextIndex = block->getChildren()->getIterable()->indexOf(next);

        if(!prev) CHECK(prevIndex == NONE);
        else CHECK(prevIndex + 1 == here);
        if(!next) CHECK(nextIndex == NONE);
        else CHECK(here + 1 == nextIndex);
    }
};

TEST_CASE("position validation for simple main with default Position type", "[chunk][fast]") {
    GroupRegistry::getInstance()->muteAllSettings();

    PositionFactory::setInstance(PositionFactory());

    ElfMap elf(TESTDIR "hi0");

    Conductor conductor;
    conductor.parseExecutable(&elf);

    auto module = conductor.getProgram()->getMain();
    auto func = CIter::named(module->getFunctionList())->find("main");

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

            PositionFactory::setInstance(PositionFactory(testCase.mode));

            ElfMap elf(TESTDIR "hi0");

            Conductor conductor;
            conductor.parseExecutable(&elf);

            auto module = conductor.getProgram()->getMain();
            auto func = CIter::named(module->getFunctionList())->find("main");

            SECTION("position validation immediately after disassembly") {
                CheckAddressIntegrity pass;
                func->accept(&pass);  // check that positions sum up correctly
                CheckPrevNextIntegrity pass2;
                func->accept(&pass2);  // check integrity of prev/next/parent pointers
            }

            SECTION("position validation after setting address to 0x4000000") {
                ChunkMutator(func).setPosition(0x4000000);

                CheckAddressIntegrity pass;
                func->accept(&pass);
            }

            auto breakInstr = makeBreakInstr();
            auto firstBlock = func->getChildren()->getIterable()->get(0);
            auto firstInstr = firstBlock->getChildren()->getIterable()->get(0);
            auto secondInstr = firstBlock->getChildren()->getIterable()->get(1);
            //GroupRegistry::getInstance()->applySetting("disasm", 9);
            //GroupRegistry::getInstance()->applySetting("chunk", 9);

            SECTION("position validation after calling insertAfter()") {
                /*PositionFactory *positionFactory = PositionFactory::getInstance();
                breakInstr->setPosition(positionFactory->makePosition(
                    firstInstr, breakInstr, firstInstr->getSize()));*/

                ChunkMutator(firstBlock).insertAfter(firstInstr, breakInstr);

                CheckAddressIntegrity pass;
                func->accept(&pass);
                CheckPrevNextIntegrity pass2;
                func->accept(&pass2);
            }

            SECTION("position validation after calling insertBefore()") {
                //ChunkDumper dump;
                //func->accept(&dump);

                ChunkMutator(firstBlock).insertBefore(secondInstr, breakInstr);

                //func->accept(&dump);

                CheckAddressIntegrity pass;
                func->accept(&pass);
                CheckPrevNextIntegrity pass2;
                firstBlock->accept(&pass2);
            }

            SECTION("position validation after calling insertBefore() the first") {
                ChunkMutator(firstBlock).insertBefore(firstInstr, breakInstr);

                CheckAddressIntegrity pass;
                func->accept(&pass);
                CheckPrevNextIntegrity pass2;
                firstBlock->accept(&pass2);
            }

            auto secondBlock = func->getChildren()->getIterable()->get(1);

            SECTION("position validation after calling prepend() in second block") {
                ChunkMutator(secondBlock).prepend(breakInstr);

                CheckAddressIntegrity pass;
                func->accept(&pass);
            }

            PositionFactory::setInstance(PositionFactory());
        }
    }
}
