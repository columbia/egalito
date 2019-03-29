#include "profileinstrument.h"
#include "operation/addinline.h"
#include "operation/mutator.h"
#include "disasm/disassemble.h"
#include "chunk/module.h"
#include "instr/concrete.h"
#include "log/log.h"

void ProfileInstrumentPass::visit(Function *function) {
    if(function->getName() == "_init") return;
    if(function->getName() == "_fini") return;
    if(function->getName() == "__libc_csu_init") return;
    if(function->getName() == "__libc_csu_fini") return;

    auto module = static_cast<Module *>(function->getParent()->getParent());
    auto section = createDataSection(module);

    ChunkAddInline ai({}, [this, section] (unsigned int stackBytesAdded) {
        //auto instr = Disassemble::instruction({0xff, 0x05, 0x00, 0x00, 0x00, 0x00});
        DisasmHandle handle(true);
        auto instr = new Instruction();
        auto sem = new LinkedInstruction(instr);
        sem->setAssembly(DisassembleInstruction(handle).makeAssemblyPtr(
            std::vector<unsigned char>{0xff, 0x05, 0x00, 0x00, 0x00, 0x00}));
        sem->setLink(addVariable(section));
        sem->setIndex(0);
        instr->setSemantic(sem);

        return std::vector<Instruction *>{ instr };
    });
	auto block1 = function->getChildren()->getIterable()->get(0);
	auto instr1 = block1->getChildren()->getIterable()->get(0);
    ai.insertBefore(instr1, true);

    {
        ChunkMutator(function, true);
    }

	auto instr0 = block1->getChildren()->getIterable()->get(0);
    auto sem = static_cast<LinkedInstruction *>(instr0->getSemantic());
    sem->regenerateAssembly();
    LOG(0, "adding profiling to function [" << function->getName()
        << "] using global var " 
        << std::hex << sem->getLink()->getTargetAddress());
}

#define DATA_REGION_ADDRESS 0x30000000
#define DATA_REGION_NAME ("region-" #DATA_REGION_ADDRESS)
#define DATA_SECTION_NAME ".profiling"

DataSection *ProfileInstrumentPass::createDataSection(Module *module) {
    auto regionList = module->getDataRegionList();
    if(auto section = regionList->findDataSection(DATA_SECTION_NAME)) {
        return section;
    }

    auto region = new DataRegion(DATA_REGION_ADDRESS);
    region->setPosition(new AbsolutePosition(DATA_REGION_ADDRESS));
    regionList->getChildren()->add(region);
    region->setParent(regionList);

    auto section = new DataSection();
    section->setName(DATA_SECTION_NAME);
    section->setAlignment(0x8);
    section->setPermissions(SHF_WRITE | SHF_ALLOC);
    section->setPosition(new AbsoluteOffsetPosition(section, 0));
    section->setType(DataSection::TYPE_DATA);
    region->getChildren()->add(section);
    section->setParent(region);

    return section;
}

Link *ProfileInstrumentPass::addVariable(DataSection *section) {
    auto region = static_cast<DataRegion *>(section->getParent());
    auto offset = section->getSize();
    section->setSize(section->getSize() + 8);
    region->setSize(region->getSize() + 8);

    return new DataOffsetLink(section, offset, Link::SCOPE_INTERNAL_DATA);
}
