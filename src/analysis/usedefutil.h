#ifndef EGALITO_ANALYSIS_USEDEFUTIL_H
#define EGALITO_ANALYSIS_USEDEFUTIL_H

#include "usedef.h"
#include <vector>
#include <utility>

class TreeNode;

class BackFlow {
public:
    template <typename StateType, typename FunctionType>
    static void collectDef(StateType *state, FunctionType& fn) {
        for(auto it = state->getRegDefList().cbegin();
            it != state->getRegDefList().cend();
            ++it) {

            fn(it->first, it->second);
        }
    }

    template <typename StateType, typename FunctionType>
    static void collectRef(StateType *state, FunctionType& fn) {
        for(auto it = state->getRegRefList().cbegin();
            it != state->getRegRefList().cend();
            ++it) {

            fn(it->first, it->second);
        }
    }

    template <typename StateType, typename FunctionType>
    static void collectUpDef(StateType *state, int reg, FunctionType& fn) {
        if(auto refList = state->getRegRef(reg)) {
            for(auto& s : *refList) {
                if(auto def = s->getRegDef(reg)) {
                    fn(s, reg, def);
                }
            }
        }
    }

    template <typename StateType, typename FunctionType>
    static void collectUpMemDef(StateType *state, int reg, FunctionType& fn) {
        auto deref = dynamic_cast<TreeNodeDereference *>(state->getRegDef(reg));
        if(deref) {
            MemLocation loadLoc(deref->getChild());
            if(auto refList = state->getMemRef(reg)) {
                for(auto& s : *refList) {
                    for(auto it = s->getMemDefList().cbegin();
                        it != s->getMemDefList().cend();
                        ++it) {

                        MemLocation storeLoc(it->second);
                        if(loadLoc == storeLoc) {
                            collectUpDef(s, it->first, fn);
                        }
                    }
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

template <typename PatternType>
class FlowPatternMatch {
private:
    std::vector<std::vector<FlowMatchResult>> list;
public:
    void operator()(UDState *state, int reg, TreeNode *tree) {
        TreeCapture cap;
        if(PatternType::matches(tree, cap)) {
            list.emplace_back(std::vector<FlowMatchResult> {});
            for(size_t i = 0; i < cap.getCount(); ++i) {
                list.back().emplace_back(state, cap.get(i));
            }
        }
    }
    const std::vector<std::vector<FlowMatchResult>>& getList() const
        { return list; }
    size_t getCount() const { return list.size(); }
    const std::vector<FlowMatchResult>& get(int n) const
        { return list[n]; }
};

template <typename PatternType>
class FlowPatternDeepMatch {
private:
    std::vector<std::vector<FlowMatchResult>> list;

    typedef TreePatternUnary<TreeNodeDereference,
        TreePatternBinary<TreeNodeAddition,
            TreePatternTerminal<TreeNodePhysicalRegister>,
            TreePatternTerminal<TreeNodeConstant>
        >
    > PointerDerefenceForm;

public:
    void operator()(UDState *state, int reg, TreeNode *tree) {
        TreeCapture cap;
        if(PatternType::matches(tree, cap)) {
            list.emplace_back(std::vector<FlowMatchResult> {});
            for(size_t i = 0; i < cap.getCount(); ++i) {
                list.back().emplace_back(state, cap.get(i));
            }
        }
        else {
            BackFlow::collectUpMemDef(state, reg, *this);
        }
    }
    const std::vector<std::vector<FlowMatchResult>>& getList() const
        { return list; }
    size_t getCount() const { return list.size(); }
    const std::vector<FlowMatchResult>& get(int n) const
        { return list[n]; }
};

#endif
