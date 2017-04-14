#ifndef EGALITO_ANALYSIS_FLOW_H
#define EGALITO_ANALYSIS_FLOW_H

#include <memory>
#include "instr/register.h"
#include "analysis/slicing.h"

class Flow {
private:
    Register reg;
    SearchState *state;

public:
    Flow(Register reg, SearchState *state) : reg(reg), state(state) {}
    virtual ~Flow() {};
    void source(bool overwriteTarget);

    bool isValid() const { return reg != INVALID_REGISTER; }
    bool interested() const;
    void markAsInteresting();
    void forget();

    virtual void channel(Flow *up, bool overwriteTarget) = 0;
    virtual void confluence(Flow *up1, Flow *up2, bool overwriteTarget) = 0;
    virtual void confluence(Flow *up1, Flow *up2, Flow *up3,
                            bool overwriteTarget) = 0;
};

class ForwardFlow : public Flow {
public:
    ForwardFlow(Register reg, SearchState *state) : Flow(reg, state) {}

    virtual void channel(Flow *up, bool overwriteTarget);
    virtual void confluence(Flow *up1, Flow *up2, bool overwriteTarget);
    virtual void confluence(Flow *up1, Flow *up2, Flow *up3,
                            bool overwriteTarget);
};

class BackwardFlow : public Flow {
public:
    BackwardFlow(Register reg, SearchState *state) : Flow(reg, state) {}

    virtual void channel(Flow *up, bool overwriteTarget);
    virtual void confluence(Flow *up1, Flow *up2, bool overwriteTarget);
    virtual void confluence(Flow *up1, Flow *up2, Flow *up3,
                            bool overwriteTarget);
};


class FlowFactory {
public:
    virtual Flow* makeFlow(Register reg, SearchState *state) = 0;
    virtual Flow* makeFlow(unsigned int reg, SearchState *state) = 0;
    virtual ~FlowFactory() {}
};

class ForwardFlowFactory : public FlowFactory {
    virtual Flow* makeFlow(Register reg, SearchState *state) {
        return new ForwardFlow(reg, state);
    }
    virtual Flow* makeFlow(unsigned int reg, SearchState *state) {
        return new ForwardFlow(static_cast<Register>(reg), state);
    }
};

class BackwardFlowFactory : public FlowFactory {
    virtual Flow* makeFlow(Register reg, SearchState *state) {
        return new BackwardFlow(reg, state);
    }
    virtual Flow* makeFlow(unsigned int reg, SearchState *state) {
        return new BackwardFlow(static_cast<Register>(reg), state);
    }
};
#endif
