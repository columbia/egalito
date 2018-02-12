#ifndef EGALITO_ANALYSIS_USEDEF_H
#define EGALITO_ANALYSIS_USEDEF_H

#include <vector>
#include <map>
#include "controlflow.h"
#include "slicingmatch.h"
#include "instr/register.h"
#include "instr/assembly.h"

class Module;
class Function;
class Instruction;
class TreeNode;

class UDState;


// Must
class DefList {
private:
    typedef std::map<int, TreeNode *> ListType;
    ListType list;
public:
    void set(int reg, TreeNode *tree);
    void del(int reg);
    TreeNode *get(int reg) const;

    size_t size() const { return list.size(); }
    ListType::iterator begin() { return list.begin(); }
    ListType::iterator end() { return list.end(); }
    ListType::const_iterator begin() const { return list.cbegin(); }
    ListType::const_iterator end() const { return list.cend(); }
    ListType::const_iterator cbegin() const { return list.cbegin(); }
    ListType::const_iterator cend() const { return list.cend(); }
    void dump() const;
};

// May: evaluation must be delayed until all use-defs are determined
class RefList {
private:
    typedef std::map<int, std::vector<UDState *>> ListType;
    ListType list;
public:
    void set(int reg, UDState *origin);
    void add(int reg, UDState *origin);
    bool addIfExist(int reg, UDState *origin);
    void del(int reg);
    void clear();
    const std::vector<UDState *>& get(int reg) const;

    ListType::iterator begin() { return list.begin(); }
    ListType::iterator end() { return list.end(); }
    ListType::const_iterator begin() const { return list.cbegin(); }
    ListType::const_iterator end() const { return list.cend(); }
    ListType::const_iterator cbegin() const { return list.cbegin(); }
    ListType::const_iterator cend() const { return list.cend(); }
    size_t getCount() const { return list.size(); }
    void dump() const;
};

// May
class UseList {
private:
    typedef std::map<int, std::vector<UDState *>> ListType;
    ListType list;
public:
    void add(int reg, UDState *state);
    void del(int reg, UDState *state);
    const std::vector<UDState *>& get(int reg) const;

    ListType::iterator begin() { return list.begin(); }
    ListType::iterator end() { return list.end(); }
    ListType::const_iterator begin() const { return list.cbegin(); }
    ListType::const_iterator end() const { return list.cend(); }
    ListType::const_iterator cbegin() const { return list.cbegin(); }
    ListType::const_iterator cend() const { return list.cend(); }
    size_t getCount() const { return list.size(); }
    void dump() const;
};


class MemOriginList {
private:
    struct MemOrigin {
        TreeNode *place;
        UDState *origin;

        MemOrigin(TreeNode *place, UDState *origin)
            : place(place), origin(origin) {}
    };
    typedef std::vector<MemOrigin> ListType;
    ListType list;

public:
    void set(TreeNode *place, UDState *origin);
    void add(TreeNode *place, UDState *origin);
    void addList(const MemOriginList& other);
    void del(TreeNode *place);
    void clear();

    ListType::iterator begin() { return list.begin(); }
    ListType::iterator end() { return list.end(); }
    ListType::const_iterator begin() const { return list.cbegin(); }
    ListType::const_iterator end() const { return list.cend(); }
    ListType::const_iterator cbegin() const { return list.cbegin(); }
    ListType::const_iterator cend() const { return list.cend(); }
    void dump() const;
};

class UDState {
public:
    virtual ControlFlowNode *getNode() = 0;
    virtual Instruction *getInstruction() const = 0;

    virtual void addRegDef(int reg, TreeNode *tree) = 0;
    virtual TreeNode *getRegDef(int reg) const = 0;
    virtual void delRegDef(int reg) = 0;
    virtual const DefList &getRegDefList() const = 0;
    virtual void addRegRef(int reg, UDState *origin) = 0;
    virtual void delRegRef(int reg) = 0;
    virtual const std::vector<UDState *>& getRegRef(int reg) const = 0;
    virtual const RefList& getRegRefList() const = 0;
    virtual void addRegUse(int reg, UDState *state) = 0;
    virtual void delRegUse(int reg, UDState *state) = 0;
    virtual const std::vector<UDState *>& getRegUse(int reg) const = 0;
    virtual const UseList &getRegUseList() const = 0;

    virtual void addMemDef(int reg, TreeNode *tree) = 0;
    virtual TreeNode *getMemDef(int reg) const = 0;
    virtual const DefList& getMemDefList() const = 0;
    virtual void addMemRef(int reg, UDState *origin) = 0;
    virtual void delMemRef(int reg) = 0;
    virtual const std::vector<UDState *>& getMemRef(int reg) const = 0;
    virtual const RefList& getMemRefList() const = 0;
    virtual void addMemUse(int reg, UDState *state) = 0;
    virtual const std::vector<UDState *>& getMemUse(int reg) const = 0;
    virtual const UseList& getMemUseList() const = 0;

    virtual void dumpState() const {}
};

class RegState : public UDState {
private:
    ControlFlowNode *node;
    Instruction *instruction;

    DefList regList;
    RefList regRefList;
    UseList regUseList;

public:
    RegState(ControlFlowNode *node, Instruction *instruction)
        : UDState(), node(node), instruction(instruction) {}

    virtual ControlFlowNode *getNode() { return node; }
    virtual Instruction *getInstruction() const { return instruction; }

    virtual void addRegDef(int reg, TreeNode *tree)
        { regList.set(reg, tree); }
    virtual TreeNode *getRegDef(int reg) const
        { return regList.get(reg); }
    virtual void delRegDef(int reg)
        { regList.del(reg); }
    virtual const DefList &getRegDefList() const
        { return regList; }
    virtual void addRegRef(int reg, UDState *origin)
        { regRefList.add(reg, origin); }
    virtual void delRegRef(int reg)
        { regRefList.del(reg); }
    virtual const std::vector<UDState *>& getRegRef(int reg) const
        { return regRefList.get(reg); }
    virtual const RefList& getRegRefList() const
        { return regRefList; }
    virtual void addRegUse(int reg, UDState *state)
        { regUseList.add(reg, state); }
    virtual void delRegUse(int reg, UDState *state)
        { regUseList.del(reg, state); }
    virtual const std::vector<UDState *>& getRegUse(int reg) const
        { return regUseList.get(reg); }
    virtual const UseList &getRegUseList() const
        { return regUseList; }

    virtual void addMemDef(int reg, TreeNode *tree) {}
    virtual TreeNode *getMemDef(int reg) const
        { return nullptr; }
    virtual const DefList &getMemDefList() const
        { static DefList emptyList; return emptyList; }
    virtual void addMemRef(int reg, UDState *origin) {}
    virtual void delMemRef(int reg) {}
    virtual const std::vector<UDState *>& getMemRef(int reg) const
        { static std::vector<UDState *> emptyList; return emptyList; }
    virtual const RefList& getMemRefList() const
        { static RefList emptyList; return emptyList; }
    virtual void addMemUse(int reg, UDState *state) {}
    virtual const std::vector<UDState *>& getMemUse(int reg) const
        { static std::vector<UDState *> emptyList; return emptyList; }
    virtual const UseList& getMemUseList() const
        { static UseList emptyList; return emptyList; }

    virtual void dumpState() const { dumpRegState(); }

protected:
    void dumpRegState() const;
};

class RegMemState : public RegState {
private:
    DefList memList;
    RefList memRefList;
    UseList memUseList;

public:
    RegMemState(ControlFlowNode *node, Instruction *instruction)
        : RegState(node, instruction) {}

    virtual void addMemDef(int reg, TreeNode *tree)
        { memList.set(reg, tree); }
    virtual TreeNode *getMemDef(int reg) const
        { return memList.get(reg); }
    virtual const DefList &getMemDefList() const
        { return memList; }
    virtual void addMemRef(int reg, UDState *origin)
        { memRefList.add(reg, origin); }
    virtual void delMemRef(int reg)
        { memRefList.del(reg); }
    virtual const std::vector<UDState *>& getMemRef(int reg) const
        { return memRefList.get(reg); }
    virtual const RefList& getMemRefList() const
        { return memRefList; }
    virtual void addMemUse(int reg, UDState *state)
        { memUseList.add(reg, state); }
    virtual const std::vector<UDState *>& getMemUse(int reg) const
        { return memUseList.get(reg); }
    virtual const UseList& getMemUseList() const
        { return memUseList; }

    virtual void dumpState() const
        { dumpRegState(); dumpMemState(); }

private:
    void dumpMemState() const;
};

class UDConfiguration {
private:
    ControlFlowGraph *cfg;
    bool allEnabled;
    std::map<int, bool> enabled;
    bool trackPartialUDChains;

public:
    UDConfiguration(ControlFlowGraph *cfg, const std::vector<int> &idList = {});

    ControlFlowGraph *getCFG() const { return cfg; }
    bool isEnabled(int id) const;
};

class UDWorkingSet {
private:
    std::vector<RefList> nodeExposedRegSetList;
    std::vector<MemOriginList> nodeExposedMemSetList;
    bool trackPartialUDChains;

    RefList *regSet;
    MemOriginList *memSet;

public:
    UDWorkingSet(ControlFlowGraph *cfg, bool trackPartial = false)
        : nodeExposedRegSetList(cfg->getCount()),
          nodeExposedMemSetList(cfg->getCount()),
          trackPartialUDChains(trackPartial),
          regSet(nullptr), memSet(nullptr) {}
    virtual ~UDWorkingSet() {}

    void transitionTo(ControlFlowNode *node);
    bool shouldTrackPartialUDChains() const { return trackPartialUDChains; }

    void setAsRegSet(int reg, UDState *origin)
        { regSet->set(reg, origin); }
    void addToRegSet(int reg, UDState *origin)
        { regSet->add(reg, origin); }
    const std::vector<UDState *>& getRegSet(int reg) const
        { return regSet->get(reg); }
    const RefList& getExposedRegSet(int id) const
        { return nodeExposedRegSetList[id]; }

    void setAsMemSet(TreeNode *place, UDState *origin)
        { memSet->set(place, origin); }
    void addToMemSet(TreeNode *place, UDState *origin)
        { memSet->add(place, origin); }
    void copyFromMemSetFor(UDState *state, int reg, TreeNode *place);
    const MemOriginList& getExposedMemSet(int id) const
        { return nodeExposedMemSetList[id]; }

    void dumpSet() const;

    virtual UDState *getState(Instruction *instruction)
        { return nullptr; }
};

class UDRegMemWorkingSet : public UDWorkingSet {
private:
    Function *function;
    ControlFlowGraph *cfg;
    std::map<Instruction *, size_t> stateListIndex;
    typedef std::vector<RegMemState> StateListType;
    StateListType stateList;
public:
    UDRegMemWorkingSet(Function *function, ControlFlowGraph *cfg,
        bool trackPartial = false);
    virtual ~UDRegMemWorkingSet() {}

    virtual UDState *getState(Instruction *instruction);
    const StateListType &getStateList() const { return stateList; }
    Function *getFunction() const { return function; }
    ControlFlowGraph *getCFG() const { return cfg; }
};

class UseDef {
public:
    typedef void (UseDef::*HandlerType)(UDState *state, AssemblyPtr assembly);

private:
    UDConfiguration *config;
    UDWorkingSet *working;

    const static std::map<int, HandlerType> handlers;

public:
    UseDef(UDConfiguration *config, UDWorkingSet *working)
        : config(config), working(working) {}

    void analyze(const std::vector<std::vector<int>>& order);

    template <typename ActualType>
    ActualType *getWorkingSet() const
        { return dynamic_cast<ActualType *>(working); }

    void cancelUseDefReg(UDState *state, int reg);

private:
    void analyzeGraph(const std::vector<int>& order);
    void fillState(UDState *state);
    bool callIfEnabled(UDState *state, Instruction *instruction);

    void fillImm(UDState *state, AssemblyPtr assembly);
    void fillReg(UDState *state, AssemblyPtr assembly);
    void fillRegToReg(UDState *state, AssemblyPtr assembly);
    void fillMemToReg(UDState *state, AssemblyPtr assembly, size_t width);
    void fillImmToReg(UDState *state, AssemblyPtr assembly);
    void fillRegRegToReg(UDState *state, AssemblyPtr assembly);
    void fillMemImmToReg(UDState *state, AssemblyPtr assembly);
    void fillRegToMem(UDState *state, AssemblyPtr assembly, size_t width);
    void fillRegImmToReg(UDState *state, AssemblyPtr assembly);
    void fillRegRegToMem(UDState *state, AssemblyPtr assembly);
    void fillMemToRegReg(UDState *state, AssemblyPtr assembly);
    void fillRegRegImmToMem(UDState *state, AssemblyPtr assembly);
    void fillRegRegRegToReg(UDState *state, AssemblyPtr assembly);
    void fillMemImmToRegReg(UDState *state, AssemblyPtr assembly);

    void defReg(UDState *state, int reg, TreeNode *tree);
    void useReg(UDState *state, int reg);
    void defMem(UDState *state, TreeNode *place, int reg);
    void useMem(UDState *state, TreeNode *place, int reg);

    TreeNode *shiftExtend(TreeNode *tree, arm64_shifter type,
        unsigned int value);

#ifdef ARCH_X86_64
    size_t inferAccessWidth(const cs_x86_op *op);
    std::tuple<int, size_t> getPhysicalRegister(int reg);
    TreeNode *makeMemTree(UDState *state, const x86_op_mem& mem);
    void fillAddOrSub(UDState *state, AssemblyPtr assembly);
    void fillAnd(UDState *state, AssemblyPtr assembly);
    void fillBsf(UDState *state, AssemblyPtr assembly);
    void fillBt(UDState *state, AssemblyPtr assembly);
    void fillCall(UDState *state, AssemblyPtr assembly);
    void fillCmp(UDState *state, AssemblyPtr assembly);
    void fillInc(UDState *state, AssemblyPtr assembly);
    void fillJa(UDState *state, AssemblyPtr assembly);
    void fillJae(UDState *state, AssemblyPtr assembly);
    void fillJb(UDState *state, AssemblyPtr assembly);
    void fillJbe(UDState *state, AssemblyPtr assembly);
    void fillJe(UDState *state, AssemblyPtr assembly);
    void fillJne(UDState *state, AssemblyPtr assembly);
    void fillJg(UDState *state, AssemblyPtr assembly);
    void fillJge(UDState *state, AssemblyPtr assembly);
    void fillJl(UDState *state, AssemblyPtr assembly);
    void fillJle(UDState *state, AssemblyPtr assembly);
    void fillJmp(UDState *state, AssemblyPtr assembly);
    void fillLea(UDState *state, AssemblyPtr assembly);
    void fillMov(UDState *state, AssemblyPtr assembly);
    void fillMovabs(UDState *state, AssemblyPtr assembly);
    void fillMovsxd(UDState *state, AssemblyPtr assembly);
    void fillMovzx(UDState *state, AssemblyPtr assembly);
    void fillTest(UDState *state, AssemblyPtr assembly);
    void fillPush(UDState *state, AssemblyPtr assembly);
    void fillXor(UDState *state, AssemblyPtr assembly);
#endif

#ifdef ARCH_AARCH64
    void fillAddOrSub(UDState *state, AssemblyPtr assembly);
    void fillAdr(UDState *state, AssemblyPtr assembly);
    void fillAdrp(UDState *state, AssemblyPtr assembly);
    void fillAnd(UDState *state, AssemblyPtr assembly);
    void fillBl(UDState *state, AssemblyPtr assembly);
    void fillBlr(UDState *state, AssemblyPtr assembly);
    void fillB(UDState *state, AssemblyPtr assembly);
    void fillBr(UDState *state, AssemblyPtr assembly);
    void fillCbz(UDState *state, AssemblyPtr assembly);
    void fillCbnz(UDState *state, AssemblyPtr assembly);
    void fillCmp(UDState *state, AssemblyPtr assembly);
    void fillCsel(UDState *state, AssemblyPtr assembly);
    void fillCset(UDState *state, AssemblyPtr assembly);
    void fillEor(UDState *state, AssemblyPtr assembly);
    void fillLdaxr(UDState *state, AssemblyPtr assembly);
    void fillLdp(UDState *state, AssemblyPtr assembly);
    void fillLdr(UDState *state, AssemblyPtr assembly);
    void fillLdrh(UDState *state, AssemblyPtr assembly);
    void fillLdrb(UDState *state, AssemblyPtr assembly);
    void fillLdrsw(UDState *state, AssemblyPtr assembly);
    void fillLdrsh(UDState *state, AssemblyPtr assembly);
    void fillLdrsb(UDState *state, AssemblyPtr assembly);
    void fillLdur(UDState *state, AssemblyPtr assembly);
    void fillLsl(UDState *state, AssemblyPtr assembly);
    void fillMadd(UDState *state, AssemblyPtr assembly);
    void fillMov(UDState *state, AssemblyPtr assembly);
    void fillMrs(UDState *state, AssemblyPtr assembly);
    void fillNop(UDState *state, AssemblyPtr assembly);
    void fillOrr(UDState *state, AssemblyPtr assembly);
    void fillRet(UDState *state, AssemblyPtr assembly);
    void fillStp(UDState *state, AssemblyPtr assembly);
    void fillStr(UDState *state, AssemblyPtr assembly);
    void fillStrb(UDState *state, AssemblyPtr assembly);
    void fillStrh(UDState *state, AssemblyPtr assembly);
    void fillSxtw(UDState *state, AssemblyPtr assembly);
    void fillUbfiz(UDState *state, AssemblyPtr assembly);
#endif
};

class MemLocation {
private:
    TreeNode *reg;
    long int offset;

public:
    MemLocation(TreeNode *tree) : reg(nullptr), offset(0) { extract(tree); }
    bool operator==(const MemLocation& other) const
        { return this->reg->equal(other.reg) && this->offset == other.offset; }
    bool operator!=(const MemLocation& other) const
        { return !this->reg->equal(other.reg) || this->offset != other.offset; }
    TreeNode *getRegTree() const { return reg; }
private:
    void extract(TreeNode *tree);
};

class StateGroup {
public:
#ifdef ARCH_AARCH64
    static bool isPushOrPop(const UDState *state);
    static bool isDirectCall(const UDState *state);
    static bool isIndirectCall(const UDState *state);
    static bool isCall(const UDState *state);
    static bool isExternalJump(const UDState *state, Module *module);
#endif
    static bool isJumpTableJump(const UDState *state, Module *module);
    static bool isReturn(const UDState *state);
};

#endif
