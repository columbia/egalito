#ifndef EGALITO_ANALYSIS_DOMINANCE_H
#define EGALITO_ANALYSIS_DOMINANCE_H

#include <vector>
#include <set>
#include "controlflow.h"

class Dominance {
public:
    using id_t = ControlFlow::id_t;

private:
    ControlFlowGraph *cfg;
    std::vector<id_t> idoms;    // immediate dominator
    std::vector<id_t> idMap;    // id_t => order ID

public:
    Dominance(ControlFlowGraph *cfg);
    std::vector<id_t> getDominators(id_t id);
    std::vector<id_t> getPostDominators(id_t id);

private:
    id_t intersect(id_t i1, id_t i2);

    void dump();
};
#endif
