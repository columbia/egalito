#include <cassert>
#include <typeinfo>

#include "chunk/concrete.h"
#include "instr/linked.h"

#include "permutedata.h"

#include "log/log.h"

void PermuteDataPass::visit(Module *module) {
    LOG(1, "Permuting data sections in module " << module->getName());
    // step 1: find highest address in module
    address_t highaddr = 0;

    for(auto region : CIter::children(module->getDataRegionList())) {
        highaddr = std::max(highaddr, region->getAddress() + region->getSize());
    }

    LOG(1, "\thigh address:" << highaddr);

    // step 2: create new dataregion
    DataRegion *ndr = new DataRegion();
    ndr->setPosition(new AbsolutePosition(highaddr));
    ndr->setParent(module->getDataRegionList());
    module->getDataRegionList()->getChildren()->add(ndr);

    // step 3: create new datasection to mirror original .data datasection

    ds = module->getDataRegionList()->findDataSection(".data");
    if(!ds) {
        LOG(1, "\taborting, no .data found!");
        return;
    }

    nds = new DataSection();

    nds->setType(DataSection::TYPE_DATA);
    nds->setSize(ds->getSize());
    ndr->setSize(ds->getSize());
    nds->setPosition(new AbsolutePosition(highaddr));
    nds->setName(".data.permuted");

    nds->setParent(ndr);
    ndr->getChildren()->add(nds);

    // step 4: re-create all datavariables (with empty links) in new datasection
    for(auto dv : CIter::children(ds)) {
        auto ndv = new DataVariable();
        ndv->setName(dv->getName());
        ndv->setSize(dv->getSize());
        auto pos = dynamic_cast<AbsoluteOffsetPosition *>(dv->getPosition());
        assert(pos);

        // for now we're mirroring the datavariables
        LOG(1, "\toffset: " << pos->getOffset());
        auto npos = new AbsoluteOffsetPosition(ndv, pos->getOffset());
        ndv->setPosition(npos);
        LOG(1, "\tndv address: " << ndv->getAddress());
        LOG(1, "\tnds address: " << nds->getAddress());

        ndv->setParent(nds);
        nds->getChildren()->add(ndv);

        dvmap[dv] = ndv;
    }
    // step 5: update all datavariable links
    for(auto dv : CIter::children(ds)) {
        auto link = dv->getDest();
        if(!link) continue;

        if(auto dol = dynamic_cast<DataOffsetLink *>(link)) {
            if(dol->getTarget() != ds) continue;

            off_t off = dol->getTargetAddress() - dol->getTarget()->getAddress();
            dvmap[dv]->setDest(new DataOffsetLink(nds, off));
        }
        else {
            LOG(1, "\tlink type " << typeid(*link).name() << " not handled");
        }
    }


    for(auto region : CIter::children(module->getDataRegionList())) {
        if(region == ndr) continue;

        for(auto section : CIter::children(region)) {
            for(auto var : CIter::children(section)) {
                auto link = var->getDest();
                if(!link) continue;

                var->setDest(updatedLink(link));

            }
        }
    }
    // step 6: iterate through all instructions, update all links to point to new
    //          datavariables and datasections (for dataoffsetlinks)
    recurse(module);
}


void PermuteDataPass::visit(Instruction *instr) {
    auto semantic = instr->getSemantic();
    auto li = dynamic_cast<LinkedInstruction *>(semantic);
    if(!li) return;

    li->setLink(updatedLink(li->getLink()));
}

Link *PermuteDataPass::updatedLink(Link *link) {
    if(auto nl = dynamic_cast<NormalLink *>(link)) {
        if(auto vdest = dynamic_cast<DataVariable *>(nl->getTarget())) {
            // only care about DataVariables in the .data section
            if(!dvmap.count(vdest)) return link;
        }
        else {
            LOG(1, "\tNormalLink target type: " << typeid(*nl->getTarget()).name());
        }
    }
    else if(auto dol = dynamic_cast<DataOffsetLink *>(link)) {
        // only care about DataOffsetLinks for the .data section
        if(dol->getTarget() != ds) return link;

        off_t off =
            dol->getTargetAddress() - dol->getTarget()->getAddress();
        delete link;
        return new DataOffsetLink(nds, off);
    }
    else {
        LOG(1, "\tlink type " << typeid(*link).name() << " not handled");
    }

    return link;
}
