#include <iostream>
#include "libc_resolve.h"
#include "elf/elfmap.h"
#include "conductor/conductor.h"
#include "pass/chunkpass.h"
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
        else if(link->getTarget()) {
            total ++;
        }
        else {
            unresolved ++, total ++;
        }
    }

    int getUnresolved() const { return unresolved; }
    int getTotal() const { return total; }
};

void LibcResolve::run() {
    GroupRegistry::getInstance()->muteAllSettings();

    try {
        ElfMap elf("test/hi0");

        Conductor conductor;
        conductor.parseRecursive(&elf);

        auto libc = conductor.getLibraryList()->get(
#ifdef ARCH_X86_64
            "/lib/x86_64-linux-gnu/libc.so.6"
#elif defined(ARCH_AARCH64)
            "/lib/aarch64-linux-gnu/libc.so.6"
#endif
        );
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
            std::cout << "TEST FAILED: " << pass.getUnresolved()
                << " unresolved out of " << pass.getTotal() << " links\n";
            return;
        }
        std::cout << "TEST PASSED: all " << pass.getTotal() << " links resolved\n";
    }
    catch(const char *error) {
        std::cout << "TEST FAILED: error: " << error << std::endl;
    }
}
