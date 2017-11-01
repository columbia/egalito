#ifndef EGALITO_ANALYSIS_SLICING_MATCH_H
#define EGALITO_ANALYSIS_SLICING_MATCH_H

#include <vector>
#include "slicingtree.h"

class TreeCapture {
private:
    std::vector<TreeNode *> captureList;
public:
    void add(TreeNode *node) { captureList.push_back(node); }
    void append(const TreeCapture& capture);
    TreeNode *get(int index) const { return captureList[index]; }
    size_t getCount() const { return captureList.size(); }
    bool clear() { captureList.clear(); return true; }
};

class TreePatternAny {
public:
    static bool matches(TreeNode *node, TreeCapture &capture)
        { return true; }
};

template <typename Type>
class TreePatternTerminal {
public:
    static bool matches(TreeNode *node, TreeCapture &capture)
        { return dynamic_cast<Type *>(node) != nullptr; }
};

template <typename Type>
class TreePatternAtLeastOneParent {
public:
    static bool matches(TreeNode *node, TreeCapture &capture);
};
template <typename Type>
bool TreePatternAtLeastOneParent<Type>::matches(
    TreeNode *node, TreeCapture &capture) {

    if(auto m = dynamic_cast<TreeNodeMultipleParents *>(node)) {
        for(auto parent : m->getParents()) {
            if(Type::matches(parent, capture)) return true;
        }
    }

    return false;
    //return Type::matches(node, capture);
}

template <typename Type, typename SubType>
class TreePatternUnary {
public:
    static bool matches(TreeNode *node, TreeCapture &capture);
};
template <typename Type, typename SubType>
bool TreePatternUnary<Type, SubType>::matches(
    TreeNode *node, TreeCapture &capture) {

    auto b = dynamic_cast<Type *>(node);
    return b != nullptr
        && SubType::matches(b->getChild(), capture);
}

template <typename Type, typename LeftType, typename RightType>
class TreePatternBinary {
public:
    static bool matches(TreeNode *node, TreeCapture &capture);
};
template <typename Type, typename LeftType, typename RightType>
bool TreePatternBinary<Type, LeftType, RightType>::matches(
    TreeNode *node, TreeCapture &capture) {

    auto b = dynamic_cast<Type *>(node);
    return b != nullptr
        && LeftType::matches(b->getLeft(), capture)
        && RightType::matches(b->getRight(), capture);
}

template <typename Type, typename LeftType, typename RightType>
class TreePatternBinaryAnyOrder {
public:
    static bool matches(TreeNode *node, TreeCapture &capture);
};
template <typename Type, typename LeftType, typename RightType>
bool TreePatternBinaryAnyOrder<Type, LeftType, RightType>::matches(
    TreeNode *node, TreeCapture &capture) {

    auto b = dynamic_cast<Type *>(node);
    return b != nullptr && (
        (LeftType::matches(b->getLeft(), capture)
            && RightType::matches(b->getRight(), capture))
        || (LeftType::matches(b->getRight(), capture)
            && RightType::matches(b->getLeft(), capture)));
}

template <typename Type, typename LeftType, typename RightType>
class TreePatternRecursiveBinary {
public:
    static bool matches(TreeNode *node, TreeCapture &capture);
};
template <typename Type, typename LeftType, typename RightType>
bool TreePatternRecursiveBinary<Type, LeftType, RightType>::matches(
    TreeNode *node, TreeCapture &capture) {

    auto b = dynamic_cast<Type *>(node);
    return b != nullptr
        && (TreePatternRecursiveBinary<
                Type, LeftType, RightType>::matches(b->getLeft(), capture)
            || LeftType::matches(b->getLeft(), capture))
        && RightType::matches(b->getRight(), capture);
}

template <typename Type = TreePatternAny>
class TreePatternCapture {
public:
    static bool matches(TreeNode *node, TreeCapture &capture);
};
template <typename Type>
bool TreePatternCapture<Type>::matches(
    TreeNode *node, TreeCapture &capture) {

    TreeCapture capture2;
    bool found = Type::matches(node, capture2);
    if(found) {
        capture.add(node);
        capture.append(capture2);
    }
    return found;
}

template <int Wanted>
class TreePatternRegisterIs {
public:
    static bool matches(TreeNode *node, TreeCapture &capture) {
        auto v = dynamic_cast<TreeNodeRegister *>(node);
        return v && v->getRegister() == Wanted;
    }
};

template <int Wanted>
class TreePatternPhysicalRegisterIs {
public:
    static bool matches(TreeNode *node, TreeCapture &capture) {
        auto v = dynamic_cast<TreeNodePhysicalRegister *>(node);
        return v && v->getRegister() == Wanted;
    }
};

template <unsigned long Wanted>
class TreePatternConstantIs {
public:
    static bool matches(TreeNode *node, TreeCapture &capture) {
        auto v = dynamic_cast<TreeNodeConstant *>(node);
        return v && v->getValue() == Wanted;
    }
};

#endif
