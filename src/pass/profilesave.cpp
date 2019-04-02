#include "profilesave.h"
#include "operation/addinline.h"
#include "operation/mutator.h"
#include "disasm/disassemble.h"
#include "chunk/module.h"
#include "chunk/initfunction.h"
#include "instr/concrete.h"
#include "log/log.h"

#define DATA_REGION_ADDRESS 0x30000000
#define DATA_NAMEREGION_ADDRESS 0x31000000
#define DATA_REGION_NAME ("region-" #DATA_REGION_ADDRESS)
#define DATA_SECTION_NAME ".profiling"
#define DATA_NAMESECTION_NAME ".profiling.names"

/*
	0000000000000000 <profiling_save_bytes>:
	   0:   53                      push   %rbx
	   1:   48 c7 c0 02 00 00 00    mov    $0x2,%rax
	   8:   48 8d 3d 00 00 00 00    lea    0x0(%rip),%rdi        # f <profiling_save_bytes+0xf>
	   f:   48 c7 c6 01 00 00 00    mov    $0x441,%rsi
	  16:   48 c7 c2 40 04 00 00    mov    $0x1a4,%rdx
	  1d:   0f 05                   syscall
	  1f:   48 89 c3                mov    %rax,%rbx
	  22:   48 c7 c0 01 00 00 00    mov    $0x1,%rax
	  29:   48 89 df                mov    %rbx,%rdi
	  2c:   48 8d 35 00 01 00 00    lea    0x100(%rip),%rsi        # 133 <profiling_save_bytes+0x133>
	  33:   48 c7 c2 01 01 00 00    mov    $0x101,%rdx
	  3a:   0f 05                   syscall
	  3c:   48 c7 c0 03 00 00 00    mov    $0x3,%rax
	  43:   48 89 df                mov    %rbx,%rdi
	  46:   0f 05                   syscall
	  48:   5b                      pop    %rbx
	  49:   c3                      retq

*/

#define GET_BYTE(x, shift) static_cast<unsigned char>(((x) >> (shift*8)) & 0xff)
#define GET_BYTES(x) GET_BYTE((x),0), GET_BYTE((x),1), GET_BYTE((x),2), GET_BYTE((x),3)

void ProfileSavePass::visit(Module *module) {
    auto sectionPair = getDataSections(module);
    auto section = sectionPair.first;
    auto nameSection = sectionPair.second;
    if(!section || !nameSection) {
        LOG(0, "ProfileSavePass: no profiling sections found, not instrumenting");
        return;
    }

    auto function = new Function();
    function->setName("egalito_profiling_save_bytes");
    function->setPosition(new AbsolutePosition(0x0));

    auto block = new Block();
    {
        ChunkMutator(function, true).append(block);
    }

    {
        DisasmHandle handle(true);
        ChunkMutator m(block, true);
        m.append(Disassemble::instruction({0x53}));
        m.append(Disassemble::instruction({0x48, 0xc7, 0xc0, 0x02, 0x00, 0x00, 0x00}));

        // lea 0x0(%rip), %rdi
        auto leaInstr = new Instruction();
        auto leaSem = new LinkedInstruction(leaInstr);
        leaSem->setAssembly(DisassembleInstruction(handle).makeAssemblyPtr(
            std::vector<unsigned char>{0x48, 0x8d, 0x3d, 0x00, 0x00, 0x00, 0x00}));
        leaSem->setLink(appendString(nameSection, "profile.data"));
        leaSem->setIndex(0);
        leaInstr->setSemantic(leaSem);
        m.append(leaInstr);
        
        m.append(Disassemble::instruction({0x48, 0xc7, 0xc6, 0x41, 0x04, 0x00, 0x00}));
        m.append(Disassemble::instruction({0x48, 0xc7, 0xc2, 0xa4, 0x01, 0x00, 0x00}));
        m.append(Disassemble::instruction({0x0f, 0x05}));
        m.append(Disassemble::instruction({0x48, 0x89, 0xc3}));
        m.append(Disassemble::instruction({0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00}));
        m.append(Disassemble::instruction({0x48, 0x89, 0xdf}));

	    //  lea    0x100(%rip),%rsi
        auto mov1Instr = new Instruction();
        auto mov1Sem = new LinkedInstruction(mov1Instr);
        mov1Sem->setAssembly(DisassembleInstruction(handle).makeAssemblyPtr(
            std::vector<unsigned char>{0x48, 0x8d, 0x35, 0x00, 0x01, 0x00, 0x00}));
        mov1Sem->setLink(new DataOffsetLink(section, 0, Link::SCOPE_INTERNAL_DATA));
        mov1Sem->setIndex(0);
        mov1Instr->setSemantic(mov1Sem);
        m.append(mov1Instr);

	    //  mov    $0x101,%rdx
        unsigned long size = section->getSize();
        m.append(Disassemble::instruction({0x48, 0xc7, 0xc2, GET_BYTES(size)}));

        m.append(Disassemble::instruction({0x0f, 0x05}));
        m.append(Disassemble::instruction({0x48, 0xc7, 0xc0, 0x03, 0x00, 0x00, 0x00}));
        m.append(Disassemble::instruction({0x48, 0x89, 0xdf}));
        m.append(Disassemble::instruction({0x0f, 0x05}));
        m.append(Disassemble::instruction({0x5b}));
        m.append(Disassemble::instruction({0xc3}));
    }

    module->getFunctionList()->getChildren()->add(function);
    function->setParent(module->getFunctionList());

    auto finiFunction = new InitFunction(false, function);
    module->getFiniFunctionList()->getChildren()->add(finiFunction);
    finiFunction->setParent(module->getFiniFunctionList());
}

std::pair<DataSection *, DataSection *> ProfileSavePass
    ::getDataSections(Module *module) {

    auto regionList = module->getDataRegionList();
    if(auto section = regionList->findDataSection(DATA_SECTION_NAME)) {
        if(auto nameSection = regionList->findDataSection(DATA_NAMESECTION_NAME)) {
            return std::make_pair(section, nameSection);
        }
    }

    return std::make_pair(nullptr, nullptr);
}

Link *ProfileSavePass::appendString(DataSection *nameSection,
    const std::string &name) {

    auto region = static_cast<DataRegion *>(nameSection->getParent());
    auto offset = nameSection->getSize();
    region->setSize(region->getSize() + name.length() + 1);
    nameSection->setSize(nameSection->getSize() + name.length() + 1);

    auto bytes = region->getDataBytes();
    bytes.append(name.c_str(), name.length() + 1);
    region->saveDataBytes(bytes);

    return new DataOffsetLink(nameSection, offset, Link::SCOPE_INTERNAL_DATA);
}
