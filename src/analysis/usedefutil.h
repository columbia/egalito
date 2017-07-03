#ifndef EGALITO_ANALYSIS_USEDEFUTIL_H
#define EGALITO_ANALYSIS_USEDEFUTIL_H

#include "usedef.h"
#include <vector>

class TreeNode;

struct FlowUtil {
public:
    template <typename StateType, typename FunctionType>
    static void collectUpDef(StateType *state, int reg, FunctionType& fn) {
        for(auto& s : state->getRegRef(reg)) {
            if(auto def = s->getRegDef(reg)) {
                fn(s, reg, def);
            }
        }
    }

    template <typename StateType, typename FunctionType>
    static void collectDownDef(StateType *state, int reg, FunctionType& fn) {
        for(auto& s : state->getRegUse(reg)) {
            collectDef(s, fn);
        }
    }

    template <typename StateType, typename FunctionType>
    static void collectDownMemDef(StateType *state, int reg, FunctionType& fn) {
        for(auto& s : state->getRegUse(reg)) {
            collectMemDef(s, fn);
        }
    }
};

struct FlowMatchResult {
    UDState *state;
    int reg;
    TreeNode *tree;

    FlowMatchResult(UDState *state, int reg, TreeNode *tree)
        : state(state), reg(reg), tree(tree) {}
};

class FlowPatternStore {
public:
    static void action(UDState *state, int reg,
        std::vector<std::vector<FlowMatchResult>> *store,
        const TreeCapture& capture) {

        store->emplace_back(std::vector<FlowMatchResult> {});
        for(size_t i = 0; i < capture.getCount(); ++i) {
            store->back().emplace_back(state, reg, capture.get(i));
        }
    }
};

template <typename PatternType, typename ActionType=FlowPatternStore>
class FlowPatternMatch {
private:
    std::vector<std::vector<FlowMatchResult>> list;
public:
    bool operator()(UDState *state, int reg, TreeNode *tree) {
        TreeCapture cap;
        if(PatternType::matches(tree, cap)) {
            ActionType::action(state, reg, &list, cap);
            return true;
        }
        return false;
    }
    std::vector<std::vector<FlowMatchResult>>& getList()
        { return list; }
    void clearList() { list.clear(); }
    size_t getCount() const { return list.size(); }
    const std::vector<FlowMatchResult>& get(int n) const
        { return list[n]; }
};

#endif
