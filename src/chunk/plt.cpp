#include "plt.h"
#include "elf/symbol.h"
#include "log/log.h"

std::string PLTEntry::getName() const {
    if(getTargetSymbol()) {
        return getTargetSymbol()->getName() + std::string("@plt");
    }
    else {
        return "???@plt";
    }
}

void PLTSection::parse(ElfMap *elf) {
    auto header = static_cast<Elf64_Shdr *>(elf->findSectionHeader(".plt"));
    auto section = reinterpret_cast<address_t>(elf->findSection(".plt"));

    PLTRegistry *registry = new PLTRegistry();
    for(auto r : *relocList) {
        if(r->getType() == R_X86_64_JUMP_SLOT
            || r->getType() == R_AARCH64_JUMP_SLOT) {

            LOG(1, "PLT entry at " << r->getAddress());
            registry->add(r->getAddress(), r);
        }
        else if(r->getType() == R_X86_64_IRELATIVE
            || r->getType() == R_AARCH64_IRELATIVE) {

            LOG(1, "ifunc PLT entry at " << r->getAddress());
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
            if(r && r->getSymbol()) {
                LOG(1, "Found PLT entry at " << pltAddress << " -> ["
                    << r->getSymbol()->getName() << "]");
                entryMap[pltAddress] = new PLTEntry(
                    pltAddress, r->getSymbol());
            }
        }
    }
#else
    static const size_t ENTRY_SIZE = 16;

    /* example format
        0000000000400420 <puts@plt>:
        400420:       90000090        adrp    x16, 410000 <__FRAME_END__+0xf9c8>
        400424:       f9443611        ldr     x17, [x16,#2152]
        400428:       9121a210        add     x16, x16, #0x868
        40042c:       d61f0220        br      x17
    */

    // note: we skip the first PLT entry, which is 2x the size of others
    for(size_t i = 2 * ENTRY_SIZE; i < header->sh_size; i += ENTRY_SIZE) {
        auto entry = section + i;

        LOG(1, "CONSIDER PLT entry at " << entry);
        LOG(1, "1st instr is " << (int)*reinterpret_cast<const unsigned int *>(entry));
        LOG(1, "2nd instr is " << (int)*reinterpret_cast<const unsigned int *>(entry+4*1));
        LOG(1, "3nd instr is " << (int)*reinterpret_cast<const unsigned int *>(entry+4*2));
        LOG(1, "4th instr is " << (int)*reinterpret_cast<const unsigned int *>(entry+4*3));

        if((*reinterpret_cast<const unsigned char *>(entry+3) & 0x9f) == 0x90) {
            address_t pltAddress = header->sh_addr + i;
            unsigned int bytes = *reinterpret_cast<const unsigned int *>(entry);

            address_t value = ((bytes & 0x60000000) >> 29)  // 2 low-order bits
                | ((bytes & 0xffffe0) >> (5-2));  // 19 high-order bits
            value <<= 12;
            value += (pltAddress) & ~0xfff;  // mask least 12 bits

            unsigned int bytes2 = *reinterpret_cast<const unsigned int *>(entry + 4);

            address_t value2 = ((bytes2 & 0x3ffc00) >> 10) << ((bytes2 & 0xc0000000) >> 30);
            value += value2;

            LOG(1, "VALUE might be " << value);
            Reloc *r = registry->find(value);
            if(r && r->getSymbol()) {
                LOG(1, "Found PLT entry at " << pltAddress << " -> ["
                    << r->getSymbolName() << "]");
                entryMap[pltAddress] = new PLTEntry(
                    pltAddress, r->getSymbol());
            }
        }
    }
#endif

    parsePLTGOT(elf);
}

void PLTSection::parsePLTGOT(ElfMap *elf) {
    auto header = static_cast<Elf64_Shdr *>(elf->findSectionHeader(".plt.got"));
    auto section = reinterpret_cast<address_t>(elf->findSection(".plt.got"));
    if(!header || !section) return;  // no .plt.got section

    PLTRegistry *newRegistry = new PLTRegistry();
    for(auto r : *relocList) {
        if(r->getType() == R_X86_64_GLOB_DAT) {
            LOG(1, "PLT.GOT data at " << r->getAddress());
            newRegistry->add(r->getAddress(), r);
        }
    }

    static const size_t ENTRY_SIZE = 8;

    /* example format
        0x00007ffff7a5b900:  ff 25 3a 85 37 00       jmpq   *0x37853a(%rip)
        0x00007ffff7a5b906:  66 90   xchg   %ax,%ax
    */

    for(size_t i = 0; i < header->sh_size; i += ENTRY_SIZE) {
        auto entry = section + i;

        LOG(1, "CONSIDER PLT.GOT entry at " << entry);

        if(*reinterpret_cast<const unsigned short *>(entry) == 0x25ff) {
            address_t pltAddress = header->sh_addr + i;
            address_t value = *reinterpret_cast<const unsigned int *>(entry + 2)
                + (pltAddress + 2+4);  // target is RIP-relative
            LOG(1, "PLT.GOT value would be " << value);
            Reloc *r = newRegistry->find(value);
            if(r && r->getSymbol()) {
                LOG(1, "Found PLT.GOT entry at " << pltAddress << " -> ["
                    << r->getSymbol()->getName() << "]");
                entryMap[pltAddress] = new PLTEntry(
                    pltAddress, r->getSymbol());
            }
        }
    }
}

PLTEntry *PLTSection::find(address_t address) {
    auto it = entryMap.find(address);
    return (it != entryMap.end() ? (*it).second : nullptr);
}

Reloc *PLTRegistry::find(address_t address) {
    auto it = registry.find(address);
    return (it != registry.end() ? (*it).second : nullptr);
}
