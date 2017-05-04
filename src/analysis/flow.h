#ifndef EGALITO_ANALYSIS_FLOW_H
#define EGALITO_ANALYSIS_FLOW_H

#include <memory>
#include "instr/register.h"

class SearchState;

class FlowElement {
private:
    Register reg;
    SearchState *state;

public:
    FlowElement(Register reg, SearchState *state) : reg(reg), state(state) {}
    virtual ~FlowElement() {};
    bool isValid() const { return reg != INVALID_REGISTER; }
    bool interested() const;
    void markAsInteresting();
    void forget();
};

class ForwardFlow {
public:
    static void source(FlowElement *down, bool overwriteTarget);
    static void channel(FlowElement *up, FlowElement *down, bool overwriteTarget);
    static void confluence(FlowElement *up1, FlowElement *up2,
                           FlowElement *down, bool overwriteTarget);
    static void confluence(FlowElement *up1, FlowElement *up2,
                           FlowElement *up3, FlowElement *down,
                           bool overwriteTarget);
};

class BackwardFlow {
public:
    static void source(FlowElement *down, bool overwriteTarget);
    static void channel(FlowElement *up, FlowElement *down, bool overwriteTarget);
    static void confluence(FlowElement *up1, FlowElement *up2,
                           FlowElement *down, bool overwriteTarget);
    static void confluence(FlowElement *up1, FlowElement *up2,
                           FlowElement *up3, FlowElement *down,
                           bool overwriteTarget);
};

#endif

