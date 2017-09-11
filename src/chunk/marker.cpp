#include <string.h>
#include "marker.h"
#include "chunk/dataregion.h"
#include "chunk/module.h"
#include "chunk/visitor.h"
#include "elf/elfspace.h"
#include "elf/reloc.h"
#include "instr/concrete.h"
#include "operation/find.h"

#include "log/log.h"

#define ROUND_UP_BY(x, y)   (((x) + (y) - 1) & ~((y) - 1))

Marker::Marker(Symbol *symbol)
    : symbol(symbol), dataSection(nullptr), alignment(1) {

    setPosition(new AbsolutePosition(symbol->getAddress()));
}

Marker::Marker(DataSection *dataSection, size_t alignment)
    : symbol(nullptr), dataSection(dataSection), alignment(alignment) {

    setPosition(new AbsolutePosition(inferAddress()));
}

address_t Marker::inferAddress() const {
    return ROUND_UP_BY(dataSection->getAddress() + dataSection->getSize(),
        alignment);
}

MarkerList *MarkerList::buildMarkerList(ElfMap *elf, Module *module,
    SymbolList *symbolList, RelocList *relocList) {

    LOG(1, "extracting marker symbols");

    auto list = new MarkerList();

    if(relocList) {
        for(auto r : *relocList) {
            auto sym = r->getSymbol();
            if(!sym) continue;
            if(sym->getType() != Symbol::TYPE_NOTYPE) continue;
            if(sym->getAddress() == 0) {
                LOG(1, "skipping WEAK symbol " << sym->getName());
                continue;
            }
            if(!strncmp(sym->getName(), ".LC", 3)) {
                LOG(1, "skipping compiler generated symbol " << sym->getName());
                continue;
            }

            auto base = elf->getBaseAddress();
#if 0
            auto addr = base + sym->getAddress();
            bool resolved = false;
            for(auto region : CIter::regions(module)) {
                if(CIter::spatial(region)->findContaining(addr)) {
                    LOG(1, "already resolved as a variable " << sym->getName());
                    resolved = true;
                    break;
                }
            }
            if(resolved) continue;

            Chunk *chunk = nullptr;
            if(auto inner = ChunkFind().findInnermostInsideInstruction(
                module->getFunctionList(), r->getAddress())) {
                auto instr = dynamic_cast<Instruction *>(inner);
                auto semantic = instr->getSemantic();
                if(auto linked = dynamic_cast<LinkedInstruction *>(semantic)) {
                    if(linked->getLink()->getTarget()) continue;
                }
                chunk = inner;
            }
            else {
                auto varAddr = base + r->getAddress();
                for(auto dr : CIter::regions(module)) {
                    if(auto var = dr->findVariable(varAddr)) {
                        chunk = var;
                        break;
                    }
                }
            }

            if(chunk) {
                LOG(1, "found linker defined symbol: " << sym->getName()
                    << " at " << r->getAddress());
                list->getChildren()->add(new Marker(sym));
            }
#else
            list->getChildren()->add(new Marker(sym));
#endif
        }
    }

    return list;
}

MarkerLink *MarkerList::makeMarkerLink(Module *module, Symbol *symbol) {
    auto space = module->getElfSpace();
    for(auto marker : CIter::children(space->getMarkerList())) {
        if(marker->getSymbol() == symbol) {
            return new MarkerLink(marker);
        }
    }

    auto marker = new Marker(symbol);
    space->getMarkerList()->getChildren()->add(marker);
    return new MarkerLink(marker);
}

MarkerLink *MarkerList::makeMarkerLink(Module *module, DataSection *dataSection,
    size_t alignment) {

    auto space = module->getElfSpace();
    for(auto marker : CIter::children(space->getMarkerList())) {
        if(marker->getDataSection() == dataSection
            && marker->getAlignment() == alignment) {

            return new MarkerLink(marker);
        }
    }

    auto marker = new Marker(dataSection, alignment);
    space->getMarkerList()->getChildren()->add(marker);
    return new MarkerLink(marker);
}

void MarkerList::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
