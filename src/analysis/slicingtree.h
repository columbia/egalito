#ifndef EGALITO_ANALYSIS_SLICING_TREE_H
#define EGALITO_ANALYSIS_SLICING_TREE_H

#include <iosfwd>
#include <vector>
#include <map>
#include "instr/register.h"
#include "types.h"

class TreePrinter {
private:
    int _indent;
    int _splits;
public:
    TreePrinter(int _indent = 1, int _splits = 2)
        : _indent(_indent), _splits(_splits) {}

    TreePrinter nest() const { return TreePrinter(_indent + 1, _splits - 1); }
    std::ostream &stream() const;
    void indent() const;
    bool shouldSplit() const { return _splits > 0; }
};

class TreeNode {
public:
    virtual ~TreeNode() {}
    virtual void print(const TreePrinter &p) const = 0;
    virtual bool equal(TreeNode *) = 0;
};

class TreeNodeConstant : public TreeNode {
private:
    long int value;
public:
    TreeNodeConstant(long value) : value(value) {}
    long int getValue() const { return value; }
    void setValue(long int value) { this->value = value; }
    virtual void print(const TreePrinter &p) const;
    virtual bool equal(TreeNode *tree) {
        auto t = dynamic_cast<TreeNodeConstant *>(tree);
        return t && getValue() == t->getValue();
    }
};

class TreeNodeAddress : public TreeNode {
private:
    address_t address;
public:
    TreeNodeAddress(address_t address) : address(address) {}
    address_t getValue() const { return address; }
    void setValue(address_t address) { this->address = address; }
    virtual void print(const TreePrinter &p) const;
    virtual bool equal(TreeNode *tree) {
        auto t = dynamic_cast<TreeNodeAddress *>(tree);
        return t && getValue() == t->getValue();
    }
};

class TreeNodeRegister : public TreeNode {
private:
    Register reg;
public:
    TreeNodeRegister(int reg) : reg(Register(reg)) {}
    int getRegister() const { return reg; }
    virtual void print(const TreePrinter &p) const;
    virtual bool equal(TreeNode *tree) {
        auto t = dynamic_cast<TreeNodeRegister *>(tree);
        return t && getRegister() == t->getRegister();
    }
};
class TreeNodeRegisterRIP : public TreeNodeRegister {
private:
    address_t value;
public:
    TreeNodeRegisterRIP(address_t value)
        : TreeNodeRegister(X86_REG_RIP), value(value) {}
    address_t getValue() const { return value; }
    virtual void print(const TreePrinter &p) const;
    virtual bool equal(TreeNode *tree) {
        auto t = dynamic_cast<TreeNodeRegisterRIP *>(tree);
        return t && getValue() == t->getValue();
    }
};
class TreeNodePhysicalRegister : public TreeNode {
private:
    Register reg;
    size_t width;
public:
    TreeNodePhysicalRegister(int reg, size_t width)
        : reg(Register(reg)), width(width) {}
    int getRegister() const { return reg; }
    size_t getWidth() const { return width; }
    virtual void print(const TreePrinter &p) const;
    virtual bool equal(TreeNode *tree) {
        auto t = dynamic_cast<TreeNodePhysicalRegister *>(tree);
        return t && getRegister() == t->getRegister();
    }
};

class TreeNodeUnary : public TreeNode {
private:
    TreeNode *node;
    const char *name;
public:
    TreeNodeUnary(TreeNode *node, const char *name)
        : node(node), name(name) {}
    TreeNode *getChild() const { return node; }
    const char *getName() const { return name; }
    virtual void print(const TreePrinter &p) const;
    virtual bool equal(TreeNode *tree);
};

class TreeNodeDereference : public TreeNodeUnary {
private:
    size_t width;
public:
    TreeNodeDereference(TreeNode *node, size_t width)
        : TreeNodeUnary(node, "deref"), width(width) {}
    size_t getWidth() const { return width; }
};
class TreeNodeJump : public TreeNodeUnary {
public:
    TreeNodeJump(TreeNode *node)
        : TreeNodeUnary(node, "jump") {}
};
class TreeNodeSignExtendByte : public TreeNodeUnary {
public:
    TreeNodeSignExtendByte(TreeNode *node)
        : TreeNodeUnary(node, "sxtb") {}
};
class TreeNodeSignExtendHalfWord : public TreeNodeUnary {
public:
    TreeNodeSignExtendHalfWord(TreeNode *node)
        : TreeNodeUnary(node, "sxth") {}
};
class TreeNodeSignExtendWord : public TreeNodeUnary {
public:
    TreeNodeSignExtendWord(TreeNode *node)
        : TreeNodeUnary(node, "sxtw") {}
};
class TreeNodeUnsignedExtendWord : public TreeNodeUnary {
public:
    TreeNodeUnsignedExtendWord(TreeNode *node)
        : TreeNodeUnary(node, "uxtw") {}
};

class TreeNodeBinary : public TreeNode {
private:
    TreeNode *left;
    TreeNode *right;
    const char *op;
public:
    TreeNodeBinary(TreeNode *left, TreeNode *right, const char *op)
        : left(left), right(right), op(op) {}
    TreeNode *getLeft() const { return left; }
    TreeNode *getRight() const { return right; }
    const char *getOperator() const { return op; }

    virtual void print(const TreePrinter &p) const;
    virtual bool equal(TreeNode *tree);
};

class TreeNodeAddition : public TreeNodeBinary {
public:
    TreeNodeAddition(TreeNode *left, TreeNode *right)
        : TreeNodeBinary(left, right, "+") {}
};
class TreeNodeSubtraction : public TreeNodeBinary {
public:
    TreeNodeSubtraction(TreeNode *left, TreeNode *right)
        : TreeNodeBinary(left, right, "-") {}
};
class TreeNodeMultiplication : public TreeNodeBinary {
public:
    TreeNodeMultiplication(TreeNode *left, TreeNode *right)
        : TreeNodeBinary(left, right, "*") {}
};
class TreeNodeLogicalShiftLeft : public TreeNodeBinary {
public:
    TreeNodeLogicalShiftLeft(TreeNode *left, TreeNode *right)
        : TreeNodeBinary(left, right, "<<") {}
};
class TreeNodeLogicalShiftRight : public TreeNodeBinary {
public:
    TreeNodeLogicalShiftRight(TreeNode *left, TreeNode *right)
        : TreeNodeBinary(left, right, ">>") {}
};
class TreeNodeRotateRight : public TreeNodeBinary {
public:
    TreeNodeRotateRight(TreeNode *left, TreeNode *right)
        : TreeNodeBinary(left, right, "r>>") {}
};
class TreeNodeArithmeticShiftRight : public TreeNodeBinary {
public:
    TreeNodeArithmeticShiftRight(TreeNode *left, TreeNode *right)
        : TreeNodeBinary(left, right, "a>>") {}
};
class TreeNodeAnd : public TreeNodeBinary {
public:
    TreeNodeAnd(TreeNode *left, TreeNode *right)
        : TreeNodeBinary(left, right, "&") {}
};
class TreeNodeDereferenceWithValue : public TreeNodeBinary {
private:
    size_t width;
public:
    TreeNodeDereferenceWithValue(TreeNode *left, TreeNode *right, size_t width)
        : TreeNodeBinary(left, right, "deref="), width(width) {}
    size_t getWidth() const { return width; }
};

class TreeNodeComparison : public TreeNode {
private:
    TreeNode *left;
    TreeNode *right;
public:
    TreeNodeComparison(TreeNode *left, TreeNode *right)
        : left(left), right(right) {}
    TreeNode *getLeft() const { return left; }
    TreeNode *getRight() const { return right; }

    virtual void print(const TreePrinter &p) const;
    virtual bool equal(TreeNode *tree) {
        auto t = dynamic_cast<TreeNodeComparison *>(tree);
        return t && (
            (getLeft()->equal(t->getLeft()) &&
             getRight()->equal(t->getRight()))
             ||
            (getRight()->equal(t->getLeft()) &&
              getLeft()->equal(t->getRight())));

    }
};

class TreeNodeMultipleParents : public TreeNode {
private:
    std::vector<TreeNode *> parentList;
public:
    void addParent(TreeNode *parent) { parentList.push_back(parent); }

    const std::vector<TreeNode *> &getParents() const { return parentList; }
    virtual void print(const TreePrinter &p) const;
    virtual bool equal(TreeNode *tree);
};

class TreeFactory {
private:
    std::vector<TreeNode *> trees;
    std::map<Register, TreeNodePhysicalRegister *> regTrees;

public:
    static TreeFactory& instance();

    template <typename TreeNodeType, typename... Args>
    TreeNodeType *make(Args... args) {
        TreeNodeType *n = new TreeNodeType(args...);
        trees.push_back(n);
        return n;
    }

    void clean();
    void cleanAll();

private:
    TreeFactory() {}
    ~TreeFactory() {}
    TreeFactory& operator=(const TreeFactory&);
    TreeFactory(const TreeFactory&);

    TreeNodePhysicalRegister *makeTreeNodePhysicalRegister(
        Register reg, int width);
};

template <>
inline TreeNodePhysicalRegister *TreeFactory::make(Register reg, int width) {
    return makeTreeNodePhysicalRegister(reg, width);
};

#endif
