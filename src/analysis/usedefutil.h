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
                fn(s, def);
            }
        }
    }

    template <typename StateType, typename FunctionType>
    static void collectDownDef(StateType *state, int reg, FunctionType& fn) {
        for(auto& s : state->getRegUse(reg)) {
            for(auto& def : s->getRegDefList()) {
                fn(s, def.first, def.second);
            }
        }
    }

    template <typename StateType, typename FunctionType>
    static void collectDownMemDef(StateType *state, int reg, FunctionType& fn) {
        for(auto& s : state->getRegUse(reg)) {
            for(auto& def : s->getMemDefList()) {
                fn(s, def.first, def.second);
            }
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

    template <
        typename PatternType,
        typename StateType,
        typename ActionType,
        typename... Args
    >
    static void searchDownDef(StateType *state, int reg, ActionType& fn,
        Args... args) {

        for(auto& s : state->getRegUse(reg)) {
            for(auto& def : s->getRegDefList()) {
                TreeCapture cap;
                if(PatternType::matches(def.second, cap)) {
                    if(fn(s, def.first, cap, args...)) return;
                }
            }
        }
    }
};

struct FlowMatchResult {
    UDState *state;
    TreeNode *tree;

    FlowMatchResult(UDState *state, TreeNode *tree)
        : state(state), tree(tree) {}
};

class FlowPatternStore {
public:
    typedef std::vector<std::vector<FlowMatchResult>> ResultType;

    static bool action(UDState *state,
        const TreeCapture& capture, ResultType *store) {

        store->emplace_back(std::vector<FlowMatchResult> {});
        for(size_t i = 0; i < capture.getCount(); ++i) {
            store->back().emplace_back(state, capture.get(i));
        }
        return false;   // collects all matches
    }
};

template <typename PatternType, typename ActionType=FlowPatternStore>
class FlowPatternMatch {
private:
    typename ActionType::ResultType result;
public:
    bool operator()(UDState *state, TreeNode *tree) {
        TreeCapture cap;
        if(PatternType::matches(tree, cap)) {
            return ActionType::action(state, cap, &result);
        }
        return false;
    }
    typename ActionType::ResultType& getResult() { return result; }
};

#endif
