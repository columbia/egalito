#include <cassert>
#include <typeinfo>

#include "chunk/concrete.h"
#include "instr/linked.h"

#include "permutedata.h"

#include "log/log.h"

void PermuteDataPass::visit(Module *module) {
    curModule = module;
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
    address_t lastAddress = 0;
    lastVariable = nullptr;

    // very simple heuristic: if two adjacent global variables are accessed
    // in the same function, treat them as one (i.e. remove the split point)
    std::set<GlobalVariable *> ignore;

    LOG(1, "Searching for adjacent variable accesses.");
    for(auto &func : CIter::children(module->getFunctionList())) {
        LOG(1, "\tin function " << func->getName());
        std::map<address_t, GlobalVariable *> touched;
        for(auto &block : CIter::children(func)) {
            for(auto &instr : CIter::children(block)) {
                auto sem = instr->getSemantic();
                if(!sem) continue;
                auto li = dynamic_cast<LinkedInstructionBase *>(sem);
                if(!li) continue;
                auto link = li->getLink();
                if(!link) continue;
                address_t taddress = link->getTargetAddress();

                if(auto dol = dynamic_cast<DataOffsetLink *>(link)) {
                    // TODO: more efficient way of doing this...
                    for(auto dr : CIter::children(module->getDataRegionList())) {
                        for(auto ds : CIter::children(dr)) {
                            for(auto gv : ds->getGlobalVariables()) {
                                if(gv->getRange().contains(taddress)) 
                                    touched[link->getTargetAddress()] = gv;
                            }
                        }
                    }
                }
                else if(dynamic_cast<NormalLink *>(li->getLink())) continue;
                else {
                    LOG(1, "unhandled link type " << typeid(*li->getLink()).name() << " when searching for adjacent globalvariable references");
                }
            }
        }

        LOG(1, "touched.size(): " << touched.size());
        if(touched.size() <= 1) continue;

        auto lastit = touched.begin();
        auto it = ++touched.begin();
        do {
            auto lastgv = (*lastit).second;
            auto curgv = (*it).second;
            //LOG(1, "Considering " << lastgv->getName() << "/" << curgv->getName());
            //LOG(1, "ranges:" << lastgv->getRange() << " and " << curgv->getRange());
            if(lastgv->getRange().getEnd() == curgv->getAddress()) {
                LOG(1, "merging " << lastgv->getName() << " and " << curgv->getName());
                // adjacent accesses, so we forbid the splitpoint
                ignore.insert(curgv);
            }

            lastit ++;
            it ++;
        } while(it != touched.end());
    }

    for(auto gv : ds->getGlobalVariables()) {
        if(ignore.count(gv)) continue;
        splitPoints.insert(gv->getAddress());
        if(gv->getAddress() > lastAddress) {
            lastAddress = gv->getAddress();
            lastVariable = gv;
        }
    }

    if(lastVariable == nullptr) {
        LOG(1, "Not enough non-merged global variables to perform randomization.");
        return;
    }

    immobileVariables[lastVariable->getRange()] = lastVariable;

    // TODO: propagate all immobile variables properly instead of relying
    // on the fact that only the last variable in a section is immobile.

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

    // step 5a: re-create all globalvariables in new datasection
    std::map<address_t, GlobalVariable *> newglobals;
    for(auto gv : ds->getGlobalVariables()) {
        GlobalVariable *ngv;
        if(gv->getSymbol()) {
            ngv = GlobalVariable::createSymtab(
                nds, newAddress(gv->getAddress()), gv->getSymbol());
            ngv->setDynamicSymbol(gv->getDynamicSymbol());
        }
        else {
            ngv = GlobalVariable::createDynsym(
                nds, newAddress(gv->getAddress()), gv->getDynamicSymbol());
            ngv->setDynamicSymbol(gv->getDynamicSymbol());
        }
    }

    // step 5b: re-create all datavariables (with empty links) in new datasection
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

        LOG(1, "\tdv address: " << dv->getAddress());
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
                if(!link) {
                    if(section == ds && var->getTargetSymbol()) {
                       LOG(1, "updating var w/symb @" << dvmap[var]->getAddress());
                       dvmap[var]->setTargetSymbol(var->getTargetSymbol());
                    }
                    else 
                        LOG(1, "skipping update var @" << var->getAddress() << ", null link and null symbol");
                    continue;
                }

                if(section == ds) {
                    #if 0
                    bool found = false;
                    for(auto imm : immobileVariables) {
                        if(imm.first.contains(var->getAddress())) found = true;
                    }
                    #else
                    bool found = false;
                    // only the last variable is immobile.
                    if(lastVariable->getAddress() <= var->getAddress()) found = true;
                    #endif
                    /*
                    auto it = immobileVariables.upper_bound(
                        );

                    if(it != immobileVariables.begin() &&
                        (*--it).first.contains(var->getAddress())) {*/
                    if(found) {
                        // do nothing, no updates
                        LOG(1, "skipping var update @" << var->getAddress());
                    }
                    else {
                        LOG(1, "updating var @" << dvmap[var]->getAddress() << " and killing var @" << var->getAddress());
                        dvmap[var]->setDest(updatedLink(link));
                        var->setDest(nullptr);
                    }
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

    // step 7: copy over data from original data region into new data region
    // NOTE: this only needs to be done for .data, not for (eventually) .bss
    auto dr = (DataRegion *)ds->getParent();
    const std::string &old_data = dr->getDataBytes();
    std::string new_data(ds->getSize(), '\x00');

    lastend = 0;

    for(auto nr : shuffle) {
        address_t newend = lastend + nr.getSize();

        LOG(1, "Moving data block " << nr << " to 0x" << std::hex << lastend);
        std::copy(
            old_data.begin() + ds->getOriginalOffset() + nr.getStart(),
            old_data.begin() + ds->getOriginalOffset() + nr.getEnd(),
            new_data.begin() + lastend);

        // newlayout[nr.getStart()] = Range::fromEndpoints(lastend, newend);
        lastend = newend;
    }

    ndr->saveDataBytes(new_data);

    // TODO: remove data section from data region
    curModule = nullptr;
}

void PermuteDataPass::visit(Instruction *instr) {
    auto semantic = instr->getSemantic();
    auto li = dynamic_cast<LinkedInstructionBase *>(semantic);
    if(!li) return;

    li->setLink(updatedLink(li->getLink()));
}

Link *PermuteDataPass::updatedLink(Link *link) {
    if(auto nl = dynamic_cast<NormalLink *>(link)) {
        // shouldn't have to do anything, NormalLinks won't reference ds
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

        // don't update for immobile variables
        //if(immobileVariableAddresses.count(dol->getTargetAddress())) return link;


        #if 0
        bool found = false;
        for(auto imm : immobileVariables) {
            if(imm.first.contains(dol->getTargetAddress())) found = true;
        }
        #else
        bool found = false;
        // only the last variable is immobile.
        if(lastVariable->getAddress() <= dol->getTargetAddress()) found = true;
        #endif
        /*
        auto it = immobileVariables.upper_bound(
            Range::fromPoint(dol->getTargetAddress()));

        if(it != immobileVariables.begin() &&
            (*--it).first.contains(dol->getTargetAddress())) {
            */
        if(found) {
            // do nothing, no updates
            LOG(1, "skipping var update targeting " << dol->getTargetAddress() << " in updatedLink()");
        }
        else {
            off_t off =
                dol->getTargetAddress() - dol->getTarget()->getAddress();
            // delete link;
            return new DataOffsetLink(nds, newOffset(off));
        }
    }
    else if(auto adl = dynamic_cast<AbsoluteDataLink *>(link)) {
        // only care about updating DataOffsetLinks that reference ds
        if(adl->getTarget() != ds) return link;

        off_t off =
            adl->getTargetAddress() - adl->getTarget()->getAddress();
        // delete link;
        return new AbsoluteDataLink(nds, newOffset(off));
    }
    else if(auto ml = dynamic_cast<MarkerLink *>(link)) {
        LOG(1, "XXX: MarkerLink NYI!");
        Marker *marker = ml->getMarker();

        // only care about markers to ds
        if(marker->getBase() != ds) return link;

        // XXX: assuming that we have a Marker, not one of the derived types
        Marker *newMarker = new Marker(nds, marker->getAddend());

        curModule->getMarkerList()->getChildren()->add(newMarker);

        return new MarkerLink(newMarker);

        /*LOG(1, "\tmarker base @" << marker->getBase()->getAddress());
        LOG(1, "\tmarker base type " << typeid(*marker->getBase()).name());
        
        LOG(1, "\tmarker type " << typeid(*marker).name() << " not handled");*/
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
