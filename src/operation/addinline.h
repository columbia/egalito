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
    class Modification {
    public:
        virtual ~Modification() {}
        virtual InstrList getNewCode() = 0;
        virtual RegList getClobberedRegisters() = 0;
    };

    class ModificationImpl : public Modification {
    private:
        RegList regList;
        std::function<InstrList ()> makeCodeCallback;
    public:
        ModificationImpl(RegList regList, std::function<InstrList ()> callback)
            : regList(regList), makeCodeCallback(callback) {}
        virtual InstrList getNewCode() { return makeCodeCallback(); }
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
    ~ChunkAddInline() { delete modification; }

    void insertBefore(Instruction *point, bool beforeJumpTo);
    void insertAfter(Instruction *point);

    static Modification *makeModification(std::vector<Register> regList,
        std::function<std::vector<Instruction *> ()> generator);
private:
    std::vector<Instruction *> getFullCode(Instruction *point);
    void extendList(std::vector<Instruction *> &list,
        const std::vector<Instruction *> &additions);
};

#endif
