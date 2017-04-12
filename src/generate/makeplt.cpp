#include "makeplt.h"
#include "section.h"
#include "elf/reloc.h"
#include "elf/elfspace.h"
#include "log/log.h"

void MakeOriginalPLT::makePLT(ElfSpace *space, PLTList *pltList,
    SymbolTableSection *dynsym) {

    auto elf = space->getElfMap();
    auto section = (elf->findSection(".plt"));
    auto header = section->getHeader();
#ifdef ARCH_X86_64
    static const size_t ENTRY_SIZE = 16;
    static const size_t INITIAL_ENTRY_SIZE = 1 * ENTRY_SIZE;
#else
    static const size_t ENTRY_SIZE = 16;
    static const size_t INITIAL_ENTRY_SIZE = 2 * ENTRY_SIZE;
#endif

    /*const char *rawPLT = reinterpret_cast<const char *>(
        elf->getCopyBaseAddress() + header->sh_addr);
    pltData.append(rawPLT, INITIAL_ENTRY_SIZE);*/

    for(auto r : *space->getRelocList()) {
        if(r->getType() == R_X86_64_JUMP_SLOT
            || r->getType() == R_AARCH64_JUMP_SLOT
            || r->getType() == R_X86_64_IRELATIVE
            || r->getType() == R_AARCH64_IRELATIVE) {

            auto sym = r->getSymbol();
            auto info = dynsym->getSymbolInfo(sym);

            auto rela = makeRela(r, r->getAddend(), info.symbolIndex);
            LOG(1, "add relocation type " << r->getType() << " to "
                << r->getSymbolName());
            relocData.append(reinterpret_cast<const char *>(&rela),
                sizeof(rela));
        }
    }
}

Elf64_Rela MakeOriginalPLT::makeRela(Reloc *r, uint64_t addend,
    size_t symbolIndex) {

    Elf64_Rela rela;
    rela.r_offset   = r->getAddress();
    rela.r_info     = ELF64_R_INFO(symbolIndex, r->getType());
    rela.r_addend   = addend;
    LOG(1, "made rela offset " << rela.r_offset << ", "
        << "symbolIndex " << symbolIndex << ", addend "
        << addend);
    return std::move(rela);
}
