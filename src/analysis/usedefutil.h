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


    template <
        typename PatternType,
        typename StateType,
        typename ActionType,
        typename... Args
    >
    static void searchUpDef(StateType *state, int reg, ActionType& fn,
        Args... args) {

        for(auto& s : state->getRegRef(reg)) {
            if(auto def = s->getRegDef(reg)) {
                TreeCapture cap;
                if(PatternType::matches(def, cap)) {
                    if(fn(s, cap, args...)) break;
                }
            }
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
    typedef std::vector<std::vector<FlowMatchResult>> ResultType;

    static bool action(UDState *state, int reg,
        const TreeCapture& capture, ResultType *store) {

        store->emplace_back(std::vector<FlowMatchResult> {});
        for(size_t i = 0; i < capture.getCount(); ++i) {
            store->back().emplace_back(state, reg, capture.get(i));
        }
        return false;   // collects all matches
    }
};

template <typename PatternType, typename ActionType=FlowPatternStore>
class FlowPatternMatch {
private:
    typename ActionType::ResultType result;
public:
    bool operator()(UDState *state, int reg, TreeNode *tree) {
        TreeCapture cap;
        if(PatternType::matches(tree, cap)) {
            return ActionType::action(state, reg, cap, &result);
        }
        return false;
    }
    typename ActionType::ResultType& getResult() { return result; }
};

#endif
