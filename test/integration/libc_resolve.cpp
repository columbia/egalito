#include <iostream>
#include "libc_resolve.h"
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
#if 1
            std::cout << "unresolved link at "
                << std::hex << instruction->getAddress()
                << " in "
                << instruction->getParent()->getParent()->getName()
                << '\n';
            if(dynamic_cast<UnresolvedLink *>(link)) {
                std::cout << "UnresolveLink to "
                    << link->getTargetAddress() << '\n';
            }
            //exit(1);
#endif
        }
    }

    int getUnresolved() const { return unresolved; }
    int getTotal() const { return total; }
};

void LibcResolve::run() {
    GroupRegistry::getInstance()->muteAllSettings();

    try {
        ElfMap elf(TESTDIR "hi0");

        Conductor conductor;
        conductor.parseExecutable(&elf);
        conductor.parseLibraries();

        auto libc = conductor.getLibraryList()->getLibc();
        if(!libc) {
            std::cout << "TEST FAILED: can't locate libc.so in depends\n";
            return;
        }

        _Pass pass;
        libc->getElfSpace()->getModule()->accept(&pass);

        if(pass.getTotal() < 100) {
            std::cout << "TEST FAILED: libc doesn't have very many links?\n";
            return;
        }
        if(pass.getUnresolved() > 0) {
            std::cout << "TEST FAILED: " << std::dec << pass.getUnresolved()
                << " unresolved out of " << pass.getTotal() << " links\n";
            return;
        }
        std::cout << "TEST PASSED: all " << pass.getTotal() << " links resolved\n";
    }
    catch(const char *error) {
        std::cout << "TEST FAILED: error: " << error << std::endl;
    }
}
