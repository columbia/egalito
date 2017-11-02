#include <iomanip>
#include "dominance.h"
#include "walker.h"

#include "log/log.h"

Dominance::Dominance(ControlFlowGraph *cfg)
    : cfg(cfg), idoms(cfg->getCount(), -1), idMap(cfg->getCount(), -1) {

    SccOrder scc(cfg);
    scc.gen(0);
    LOG(10, "SCC");
    for(auto sub : scc.get()) {
        for(auto n : sub) {
            LOG0(10, " " << std::setw(3) << n);
        }
        LOG(10, "");
    }

    ReversePostorder rpo(cfg);
    rpo.gen(0);
    auto order = rpo.get()[0];
    for(size_t i = 0; i < order.size(); i++) {
        idMap[order[i]] = i;
    }

    bool changed = true;
    while(changed) {
        changed = false;
        for(auto id : order) {
            LOG(10, "id = " << id);
            if(id == 0) {
                idoms[0] = 0;
                continue;
            }
            auto node = cfg->get(id);
            bool first = true;
            ControlFlow::id_t idom = -1;
            for(auto link : node->backwardLinks()) {
                auto pred = link->getTargetID();
                if(idoms[idMap[pred]] != -1) {
                    if(first) {
                        idom = pred;
                        first = false;
                    }
                    else {
                        idom = intersect(pred, idom);
                    }
                }
            }

            if(idoms[id] != idom) {
                idoms[id] = idom;
                changed = true;
                IF_LOG(10) dump();
            }
        }
    }

    IF_LOG(10) dump();
}

ControlFlow::id_t Dominance::intersect(ControlFlow::id_t i1,
    ControlFlow::id_t i2) {

    auto finger1 = i1;
    auto finger2 = i2;

    LOG(10, "intersect " << i1 << " " << i2);

    while(finger1 != finger2) {
        if(idoms[finger1] == -1) return finger2;
        if(idoms[finger2] == -1) return finger1;

        while(idoms[finger1] != -1 && idMap[finger1] > idMap[finger2]) {
            finger1 = idoms[finger1];
        }
        while(idoms[finger2] != -1 && idMap[finger2] > idMap[finger1]) {
            finger2 = idoms[finger2];
        }
    }
    return finger1;
}

std::vector<ControlFlow::id_t> Dominance::getDominators(ControlFlow::id_t id) {
    std::vector<ControlFlow::id_t> doms;

    while(id != 0) {
        doms.push_back(id);
        id = idoms[id];
    }
    doms.push_back(0);
    return doms;
}

std::vector<ControlFlow::id_t> Dominance::getPostDominators(
    ControlFlow::id_t id) {

    Preorder po(cfg);
    po.gen(0);
    auto order = po.get()[0];
    for(size_t i = 0; i < order.size(); i++) {
        idMap[order[i]] = i;
    }

    std::vector<ControlFlowNode *> exitNodes;
    for(auto nid : order) {
        auto node = cfg->get(nid);
        bool isExit = true;
        for(auto link : node->forwardLinks()) {
            (void)link;
            isExit = false;
            break;
        }
        if(isExit) {
            exitNodes.push_back(node);
        }
    }

    auto cap = [](std::vector<ControlFlow::id_t> v1,
        std::vector<ControlFlow::id_t> v2) {

        std::vector<ControlFlow::id_t> v;
        std::set_intersection(v1.begin(), v1.end(), v2.begin(), v2.end(),
            std::back_inserter(v));

        return v;
    };

    auto pdom = getDominators(exitNodes[0]->getID());
    pdom.erase(std::remove(pdom.begin(), pdom.end(), 0), pdom.end());

    for(size_t i = 1; i <exitNodes.size(); i++) {
        auto pdom2 = getDominators(exitNodes[i]->getID());
        std::sort(pdom2.begin(), pdom2.end());
        pdom = cap(pdom, pdom2);
        if(pdom.empty()) break;
    }

    return pdom;
}


void Dominance::dump() {
    LOG(1, "idoms");
    for(auto i : idoms) {
        LOG0(1, " " << i);
    }
    LOG(1, "");
}

