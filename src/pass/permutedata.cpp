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
    highaddr = (highaddr + 0xfff) & ~0xfff;
    DataRegion *ndr = new DataRegion(highaddr);

    ndr->setPosition(new AbsolutePosition(highaddr));
    ndr->setParent(module->getDataRegionList());
    ndr->setPermissions(PF_R | PF_W);
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
    nds->setPermissions(SHF_WRITE);
    ndr->setSize(ds->getSize());
    nds->setPosition(new AbsolutePosition(highaddr));
    nds->setName(".data.permuted");

    nds->setParent(ndr);
    ndr->getChildren()->add(nds);

    // step 4: generate list of data ranges that we have to move together
    std::set<address_t> splitPoints;
    for(auto gv : ds->getGlobalVariables()) {
        splitPoints.insert(gv->getAddress());
    }

    std::vector<Range> ranges;
    address_t prev = 0;
    const address_t ds_begin = ds->getAddress();
    for(auto addr : splitPoints) {
        addr -= ds_begin;
        ranges.push_back(Range::fromEndpoints(prev, addr));
        prev = addr;
    }
    if(prev != ds->getSize()) {
        ranges.push_back(Range::fromEndpoints(prev, ds->getSize()));
    }

    // generate random new layout
    newlayout.clear();
    std::vector<Range> shuffle = ranges;
    std::random_shuffle(shuffle.begin(), shuffle.end());
    address_t lastend = 0;

    for(auto nr : shuffle) {
        address_t newend = lastend + nr.getSize();
        newlayout[nr.getStart()] = Range::fromEndpoints(lastend, newend);
        lastend = newend;
    }

    // step 5: re-create all datavariables (with empty links) in new datasection
    std::map<address_t, DataVariable *> newvars;
    for(auto dv : CIter::children(ds)) {
        auto ndv = new DataVariable();
        ndv->setName(dv->getName());
        ndv->setSize(dv->getSize());
        auto pos = dynamic_cast<AbsoluteOffsetPosition *>(dv->getPosition());
        assert(pos);

        // for now we're mirroring the datavariables
        LOG(1, "\toffset: " << pos->getOffset());
        off_t noff = newOffset(pos->getOffset());
        auto npos = new AbsoluteOffsetPosition(ndv, noff);
        ndv->setPosition(npos);
        ndv->setParent(nds);
        newvars[noff] = ndv;

        LOG(1, "\tndv address: " << ndv->getAddress());
        LOG(1, "\tnds address: " << nds->getAddress());

        dvmap[dv] = ndv;
    }
    for(auto kv : newvars) nds->getChildren()->add(kv.second);

    // update all datavariables that reference ds
    for(auto region : CIter::regions(module)) {
        for(auto section : CIter::children(region)) {
            for(auto var : CIter::children(section)) {
                auto link = var->getDest();
                if(!link) continue;

                if(section == ds) {
                    dvmap[var]->setDest(updatedLink(link));
                }
                else {
                    var->setDest(updatedLink(link));
                }
            }
        }
    }

    // step 6: iterate through all instructions, update all links to point to new
    //          datavariables and datasections (for dataoffsetlinks)
    recurse(module);
}

void PermuteDataPass::visit(Instruction *instr) {
    auto semantic = instr->getSemantic();
    auto li = dynamic_cast<LinkedInstructionBase *>(semantic);
    if(!li) return;

    li->setLink(updatedLink(li->getLink()));
}

Link *PermuteDataPass::updatedLink(Link *link) {
    if(auto nl = dynamic_cast<NormalLink *>(link)) {
        #if 0
        if(auto vdest = dynamic_cast<DataVariable *>(nl->getTarget())) {
            // only care about DataVariables in the .data section
            if(!dvmap.count(vdest)) return link;
        }
        else {
            LOG(1, "\tNormalLink target type: " << typeid(*nl->getTarget()).name());
        }
        #endif
    }
    else if(auto dol = dynamic_cast<DataOffsetLink *>(link)) {
        // only care about updating DataOffsetLinks that reference ds
        if(dol->getTarget() != ds) return link;

        off_t off =
            dol->getTargetAddress() - dol->getTarget()->getAddress();
        delete link;
        return new DataOffsetLink(nds, newOffset(off));
    }
    else if(auto adl = dynamic_cast<AbsoluteDataLink *>(link)) {
        // only care about updating DataOffsetLinks that reference ds
        if(adl->getTarget() != ds) return link;

        off_t off =
            adl->getTargetAddress() - adl->getTarget()->getAddress();
        delete link;
        return new AbsoluteDataLink(nds, newOffset(off));
    }
    else {
        LOG(1, "\tlink type " << typeid(*link).name() << " not handled");
    }

    return link;
}

address_t PermuteDataPass::newAddress(address_t address) {
    off_t offset = address - ds->getAddress();
    return nds->getAddress() + newOffset(offset);
}

address_t PermuteDataPass::newOffset(address_t offset) {
    auto it = newlayout.upper_bound(offset);
    assert(it != newlayout.begin());
    it --;

    off_t subregion_offset = offset - (*it).first;

    return (*it).second.getStart() + subregion_offset;
}
