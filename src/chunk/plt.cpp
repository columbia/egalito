#include "plt.h"
#include "elf/symbol.h"
#include "log/log.h"

std::string PLTEntry::getName() const {
    return getTargetSymbol()->getName() + std::string("@plt");
}

void PLTSection::parse(ElfMap *elf) {
    auto header = static_cast<Elf64_Shdr *>(elf->findSectionHeader(".plt"));
    auto section = reinterpret_cast<address_t>(elf->findSection(".plt"));

    PLTRegistry *registry = new PLTRegistry();
    for(auto r : *relocList) {
        if(r->getType() == R_X86_64_JUMP_SLOT) {
            LOG(1, "PLT entry at " << r->getAddress());
            registry->add(r->getAddress(), r);
        }
    }

#ifdef ARCH_X86_64
    static const size_t ENTRY_SIZE = 16;

    /* example format
        0000000000000550 <.plt>:
         550:   ff 35 b2 0a 20 00       pushq  0x200ab2(%rip)
         556:   ff 25 b4 0a 20 00       jmpq   *0x200ab4(%rip)
         55c:   0f 1f 40 00             nopl   0x0(%rax)

        0000000000000560 <puts@plt>:
         560:   ff 25 b2 0a 20 00       jmpq   *0x200ab2(%rip)
         566:   68 00 00 00 00          pushq  $0x0
         56b:   e9 e0 ff ff ff          jmpq   550 <.plt>
    */

    // note: we skip the first PLT entry, which has a different format
    for(size_t i = 1 * ENTRY_SIZE; i < header->sh_size; i += ENTRY_SIZE) {
        auto entry = section + i;

        LOG(1, "CONSIDER PLT entry at " << entry);

        if(*reinterpret_cast<const unsigned short *>(entry) == 0x25ff) {
            address_t pltAddress = header->sh_addr + i;
            address_t value = *reinterpret_cast<const unsigned int *>(entry + 2)
                + (pltAddress + 2+4);  // target is RIP-relative
            LOG(1, "PLT value would be " << value);
            Reloc *r = registry->find(value);
            if(r) {
                LOG(1, "Found PLT entry at " << pltAddress << " -> ["
                    << r->getSymbol()->getName() << "]");
                entryMap[pltAddress] = new PLTEntry(
                    pltAddress, r->getSymbol());
            }
        }
    }
#else
    #error "Not yet implemented, PLT detection for ARM"
#endif
}

PLTEntry *PLTSection::find(address_t address) {
    auto it = entryMap.find(address);
    return (it != entryMap.end() ? (*it).second : nullptr);
}

Reloc *PLTRegistry::find(address_t address) {
    auto it = registry.find(address);
    return (it != registry.end() ? (*it).second : nullptr);
}
