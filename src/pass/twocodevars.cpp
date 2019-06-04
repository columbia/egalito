#include <cstring>  // for memset
#include "twocodevars.h"
#include "operation/find2.h"
#include "log/log.h"

#define TWOCODE_GS_REGION_ADDRESS   0x32000000
#define TWOCODE_ORIG_REGION_ADDRESS 0x30000000
#define TWOCODE_NEW_REGION_ADDRESS  0x31000000
#define TWOCODE_GS_SECTION_NAME     ".twocode.gs"
#define TWOCODE_ORIG_SECTION_NAME   ".twocode.0"
#define TWOCODE_NEW_SECTION_NAME    ".twocode.1"

void TwocodeVarsPass::visit(Module *module) {
    auto program = static_cast<Program *>(module->getParent());
    auto regionList = module->getDataRegionList();

    struct {
        address_t address;
        const char *name;
        DataSection *section;
    } regionConfig[] = {
        {TWOCODE_GS_REGION_ADDRESS,     TWOCODE_GS_SECTION_NAME,    nullptr},
        {TWOCODE_ORIG_REGION_ADDRESS,   TWOCODE_ORIG_SECTION_NAME,  nullptr},
        {TWOCODE_NEW_REGION_ADDRESS,    TWOCODE_NEW_SECTION_NAME,   nullptr}
    };
    for(size_t i = 0; i < sizeof(regionConfig) / sizeof(*regionConfig); i++) {
        auto &config = regionConfig[i]; 
        if(i == 2 && !otherModule) continue;

        auto region = new DataRegion(config.address);
        region->setPosition(new AbsolutePosition(config.address));
        regionList->getChildren()->add(region);
        region->setParent(regionList);

        auto section = new DataSection();
        section->setName(config.name);
        section->setAlignment(0x8);
        section->setPermissions(SHF_WRITE | SHF_ALLOC);
        section->setPosition(new AbsoluteOffsetPosition(section, 0));
        section->setType(DataSection::TYPE_DATA);
        region->getChildren()->add(section);
        section->setParent(region);

        regionConfig[i].section = section;
    }

    // gs values
    for(auto entry : CIter::children(gsTable)) {
        LOG(0, "adding gsvalue 0x" << std::hex << entry->getTarget()->getAddress());
        addGSValue(regionConfig[0].section, entry);
    }

    // orig values
    for(auto entry : CIter::children(gsTable)) {
        auto target = entry->getTarget();
        addVariable(regionConfig[1].section, target, "$0");
    }

    // new/other values
    if(otherModule) {
        for(auto entry : CIter::children(gsTable)) {
            Function *newFunc = nullptr;
            if(auto origFunc = dynamic_cast<Function *>(entry->getTarget())) {
                newFunc = ChunkFind2(program)
                    .findFunctionInModule(origFunc->getName().c_str(), otherModule);
            }
            addVariable(regionConfig[2].section, newFunc, "$1");
        }
    }
}

void TwocodeVarsPass::addGSValue(DataSection *section, GSTableEntry *entry) {
    auto region = static_cast<DataRegion *>(section->getParent());
    //auto offset = section->getSize();
    auto offset = entry->getOffset();

    auto address = section->getAddress() + section->getSize();
    section->setSize(offset + 8);
    region->setSize(offset + 8);

    auto link = new AbsoluteNormalLink(entry->getTarget(), Link::SCOPE_WITHIN_MODULE);
    Symbol *targetSymbol = nullptr;
    if(auto function = dynamic_cast<Function *>(entry->getTarget())) {
        targetSymbol = function->getSymbol();
    }
    auto var = DataVariable::create(section, address, link, targetSymbol);
    var->setPosition(new AbsolutePosition(address));
    section->getChildren()->getIterable()->add(var);
}

void TwocodeVarsPass::addVariable(DataSection *section, Chunk *target,
    const char *suffix) {

    auto region = static_cast<DataRegion *>(section->getParent());
    auto address = section->getAddress() + section->getSize();
    section->setSize(section->getSize() + 8);
    region->setSize(region->getSize() + 8);

    if(target) {
        // auto offset = section->getSize();

        const size_t VAR_SIZE = 8;
        auto link = new AbsoluteNormalLink(target, Link::SCOPE_WITHIN_MODULE);

        Symbol *targetSymbol = nullptr;
        Symbol *nsymbol = nullptr;
        if(auto function = dynamic_cast<Function *>(target)) {
            char *name = new char[function->getName().length() + std::strlen(suffix) + 1];
            std::strcpy(name, function->getName().c_str());
            std::strcat(name, suffix);

            nsymbol = new Symbol(
                function->getAddress(), VAR_SIZE, name,
                Symbol::TYPE_OBJECT, Symbol::BIND_LOCAL, 0, 0);
            targetSymbol = function->getSymbol();

            LOG(0, "added symbol [" << name << "] for twocode");
        }

        auto var = DataVariable::create(section, address, link, nsymbol);
        var->setTargetSymbol(targetSymbol);
        var->setPosition(new AbsolutePosition(address));

        section->getChildren()->getIterable()->add(var);
    }
}
