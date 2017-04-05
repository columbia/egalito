#include <cstring>  // for memcpy
#include "plt.h"
#include "elf/symbol.h"
#include "log/log.h"

class PLTRegistry {
private:
    typedef std::map<address_t, Reloc *> RegistryType;
    RegistryType registry;
public:
    void add(address_t address, Reloc *r) { registry[address] = r; }
    Reloc *find(address_t address);
};
Reloc *PLTRegistry::find(address_t address) {
    auto it = registry.find(address);
    return (it != registry.end() ? (*it).second : nullptr);
}

PLTTrampoline::PLTTrampoline(ElfMap *sourceElf, address_t address,
    Symbol *targetSymbol, address_t gotPLTEntry) : sourceElf(sourceElf),
    target(nullptr), targetSymbol(targetSymbol), gotPLTEntry(gotPLTEntry) {

    setPosition(new AbsolutePosition(address));
}

std::string PLTTrampoline::getName() const {
    if(getTargetSymbol()) {
        return getTargetSymbol()->getName() + std::string("@plt");
    }
    else {
        return "???@plt";
    }
}

bool PLTSection::parsePLTList(ElfMap *elf, RelocList *relocList, Module *module) {
    auto pltList = PLTSection().parse(relocList, elf);
    if(pltList) {
        module->getChildren()->add(pltList);
        module->setPLTList(pltList);
        pltList->setParent(module);
    }
    return pltList != nullptr;
}

PLTList *PLTSection::parse(RelocList *relocList, ElfMap *elf) {
    auto header = static_cast<Elf64_Shdr *>(elf->findSectionHeader(".plt"));
    if(!header) return nullptr;
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

    PLTList *pltList = new PLTList();

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
                pltList->getChildren()->add(new PLTTrampoline(elf,
                    pltAddress, r->getSymbol(), value));
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

#if 0
        LOG(1, "CONSIDER PLT entry at " << entry);
        LOG(1, "1st instr is " << (int)*reinterpret_cast<const unsigned int *>(entry));
        LOG(1, "2nd instr is " << (int)*reinterpret_cast<const unsigned int *>(entry+4*1));
        LOG(1, "3nd instr is " << (int)*reinterpret_cast<const unsigned int *>(entry+4*2));
        LOG(1, "4th instr is " << (int)*reinterpret_cast<const unsigned int *>(entry+4*3));
#endif

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
                pltList->getChildren()->add(new PLTTrampoline(
                    elf, pltAddress, r->getSymbol(), value));
            }
        }
    }
#endif

    parsePLTGOT(relocList, elf, pltList);
    return pltList;
}

void PLTSection::parsePLTGOT(RelocList *relocList, ElfMap *elf,
    PLTList *pltList) {

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
                pltList->getChildren()->add(new PLTTrampoline(elf,
                    pltAddress, r->getSymbol(), value));
            }
        }
    }
}

void PLTTrampoline::writeTo(char *target) {
#ifdef ARCH_X86_64
    size_t offset = 0;
#define ADD_BYTES(data, size) \
    std::memcpy(target+offset, data, size), offset += size

    bool isIFunc = false;
    if(auto v = dynamic_cast<Function *>(this->target)) {
        if(v->getSymbol()->getType() == Symbol::TYPE_IFUNC) isIFunc = true;
        LOG(1, "making PLT entry for [" << v->getName() << "] : ifunc? " << (isIFunc ? "yes":"no"));
    }

    address_t gotPLT = getGotPLTEntry();
    if(!isIFunc) {
        // ff 25 NN NN NN NN    jmpq *0xNNNNNNNN(%rip)
        ADD_BYTES("\xff\x25", 2);
        address_t disp = gotPLT - (getAddress() + 2+4);
        ADD_BYTES(&disp, 4);

        // 68 NN NN NN NN    pushq  $0xNNNNNNNN
        //ADD_BYTES("\x68", 1);
        //address_t address = getAddress();
        //ADD_BYTES(&address, 4);
    }
    else {
        // ff 15 NN NN NN NN    callq *0xNNNNNNNN(%rip)
        ADD_BYTES("\xff\x15", 2);
        address_t disp = gotPLT - (getAddress() + 2+4);
        ADD_BYTES(&disp, 4);

        // ff e0    jmpq *%rax
        ADD_BYTES("\xff\xe0", 2);
    }

#undef ADD_BYTES
#elif defined(ARCH_AARCH64)
    static const uint32_t plt[] = {
        0x90000010, //adrp x16, .
        0xf9400211, //ldr  x17, [x16, #0]
        /* 0x91000210, */ //add x16, x16, #0
        0xd61f0220  //br x17
    };

    address_t gotPLT = getGotPLTEntry();
    address_t disp = gotPLT - (getAddress() & ~0xFFF);
    uint32_t imm = disp >> 12;

    uint32_t encoding = (imm & 0x3) << 29 | ((imm & 0x1FFFFC) << 3);

    *(uint32_t *)(target + 0) = plt[0] | encoding;

    disp = gotPLT & 0xFFF;
    imm = (disp >> 3) << 10;
    encoding = imm & ~0xFFE003FF;

    *(uint32_t *)(target + 4) = plt[1] | encoding;
    *(uint32_t *)(target + 8) = plt[2];
#endif

    LOG(1, "created PLT entry to " << std::hex << (void *)gotPLT
        << " from 0x" << getAddress());
}

