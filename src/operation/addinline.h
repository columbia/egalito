#ifndef EGALITO_OPERATION_ADDINLINE_PASS_H
#define EGALITO_OPERATION_ADDINLINE_PASS_H

#include <vector>
#include <functional>
#include "instr/instr.h"
#include "instr/register.h"

class ChunkAddInline {
public:
    typedef std::vector<Instruction *> InstrList;
    typedef std::vector<Register> RegList;
public:
    /*class InsertionState {
    private:
        unsigned int stackBytesAdded;
#ifdef ARCH_X86_64
        bool redzone;
#endif
    public:
        unsigned int getStackBytesAdded() const { return stackBytesAdded; }
    };*/

    class Modification {
    public:
        virtual ~Modification() {}
        virtual InstrList getNewCode(unsigned int stackBytesAdded) = 0;
        virtual RegList getClobberedRegisters() = 0;
    };

    class ModificationImpl : public Modification {
    private:
        RegList regList;
        std::function<InstrList (unsigned int)> makeCodeCallback;
    public:
        ModificationImpl(RegList regList, std::function<InstrList (unsigned int)> callback)
            : regList(regList), makeCodeCallback(callback) {}
        virtual InstrList getNewCode(unsigned int stackBytesAdded)
            { return makeCodeCallback(stackBytesAdded); }
        virtual RegList getClobberedRegisters() { return regList; }
    };
private:
    class SaveRestoreRegisters {
    private:
        Instruction *point;
#ifdef ARCH_X86_64
        bool redzone;
#endif
    public:
#ifdef ARCH_X86_64
        SaveRestoreRegisters(Instruction *point, bool redzone)
            : point(point), redzone(redzone) {}
#else
        SaveRestoreRegisters(Instruction *point) : point(point) {}
#endif

        InstrList getRegSaveCode(const RegList &regList);
        InstrList getRegRestoreCode(const RegList &regList);
    };
private:
    Modification *modification;
public:
    // allow this modification to be applied in multiple places.
    // takes ownership of modification and will free it.
    ChunkAddInline(Modification *modification);
    ChunkAddInline(std::vector<Register> regList,
        std::function<std::vector<Instruction *> (unsigned int)> generator);
    ~ChunkAddInline() { delete modification; }

    void insertBefore(Instruction *point, bool beforeJumpTo);
    void insertAfter(Instruction *point);
private:
    std::vector<Instruction *> getFullCode(Instruction *point);
    void extendList(std::vector<Instruction *> &list,
        const std::vector<Instruction *> &additions);
};

#endif
