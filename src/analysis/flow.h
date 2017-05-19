#ifndef EGALITO_ANALYSIS_FLOW_H
#define EGALITO_ANALYSIS_FLOW_H

#include "instr/register.h"

class SearchState;
class Memory;

class FlowElement {
public:
    virtual ~FlowElement() {};
    virtual bool isValid() const = 0;
    virtual bool interested() const = 0;
    virtual void markAsInteresting() = 0;
    virtual void forget() = 0;
};

class FlowRegElement : public FlowElement {
private:
    Register reg;
    SearchState *state;
public:
    FlowRegElement(Register reg, SearchState *state) : reg(reg), state(state) {}
    virtual bool isValid() const { return reg != INVALID_REGISTER; }
    virtual bool interested() const;
    virtual void markAsInteresting();
    virtual void forget();
};

class FlowMemElement : public FlowElement {
private:
    Memory *mem;
    SearchState *state;
public:
    FlowMemElement(Memory *mem, SearchState *state) : mem(mem), state(state) {}
    virtual bool isValid() const;
    virtual bool interested() const;
    virtual void markAsInteresting();
    virtual void forget();
};

class ForwardFlow {
public:
    static void source(FlowElement *down, bool overwriteTarget);
    static void channel(FlowElement *up, FlowElement *down, bool overwriteTarget);
    static void confluence(FlowElement *up1, FlowElement *up2,
                           FlowElement *down, bool overwriteTarget);
};

class BackwardFlow {
public:
    static void source(FlowElement *down, bool overwriteTarget);
    static void channel(FlowElement *up, FlowElement *down, bool overwriteTarget);
    static void confluence(FlowElement *up1, FlowElement *up2,
                           FlowElement *down, bool overwriteTarget);
};

#endif

