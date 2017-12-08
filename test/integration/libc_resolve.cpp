#include "framework/include.h"
#include "framework/StreamAsString.h"
#include "elf/elfmap.h"
#include "conductor/conductor.h"
#include "pass/chunkpass.h"
#include "instr/semantic.h"
#include "log/registry.h"

class _Pass : public ChunkPass {
private:
    int unresolved, total;
public:
    _Pass() : unresolved(0), total(0) {}

    void visit(Instruction *instruction) {
        auto link = instruction->getSemantic()->getLink();
        if(!link) return;

        if(dynamic_cast<PLTLink *>(link)) {
            total ++;
        }
        else if(dynamic_cast<DataOffsetLink *>(link)) {
            total ++;
        }
        else if(dynamic_cast<MarkerLink *>(link)) {
            total ++;
        }
        else if(link->getTarget()) {
            total ++;
        }
        else {
            unresolved ++, total ++;
#if 0
            std::cout << "unresolved link at "
                << std::hex << instruction->getAddress()
                << " in "
                << instruction->getParent()->getParent()->getName()
                << '\n';
            if(dynamic_cast<UnresolvedLink *>(link)) {
                std::cout << "UnresolveLink to "
                    << link->getTargetAddress() << '\n';
            }
#endif
        }
    }

    int getUnresolved() const { return unresolved; }
    int getTotal() const { return total; }
};

TEST_CASE("make sure all links in libc are resolved", "[integration][full][.]") {
    GroupRegistry::getInstance()->muteAllSettings();

    ElfMap elf(TESTDIR "hi0");

    Conductor conductor;
    conductor.parseExecutable(&elf);
    conductor.parseLibraries();

    auto libc = conductor.getProgram()->getLibc();
    REQUIRE(libc != nullptr);

    _Pass pass;
    libc->accept(&pass);

    SECTION("libc has at least a few links") {
        CHECK(pass.getTotal() > 100);
    }

    SECTION("all of libc's links are resolved") {
        INFO(std::dec << pass.getUnresolved() << " unresolved out of "
            << pass.getTotal() << " links");
        CHECK(pass.getUnresolved() == 0);
    }
}
