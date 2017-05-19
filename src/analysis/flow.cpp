#include "flow.h"
#include "analysis/slicing.h"
#include "instr/memory.h"

bool FlowRegElement::interested() const {
    if(isValid()) {
        return state->getReg(reg);
    }
    return false;
}

void FlowRegElement::markAsInteresting() {
    if(isValid()) {
        state->addReg(reg);
    }
}

void FlowRegElement::forget() {
    if(isValid()) {
        state->removeReg(reg);
    }
}

bool FlowMemElement::isValid() const {
    return (mem->getIndex() == REGISTER_SP || mem->getIndex() == REGISTER_FP);
}

bool FlowMemElement::interested() const {
    if(isValid()) {
        return state->getMem(mem->getDisplacement());
    }
    return false;
}

void FlowMemElement::markAsInteresting() {
    if(isValid()) {
        state->addMem(mem->getDisplacement());
    }
}

void FlowMemElement::forget() {
    if(isValid()) {
        state->removeMem(mem->getDisplacement());
    }
}

void BackwardFlow::source(FlowElement *down, bool overwriteTarget) {
    if(down->interested()) {
        if(overwriteTarget) {
            down->forget();
        }
    }
}
void ForwardFlow::source(FlowElement *down, bool overwriteTarget) {
    if(down->interested()) {
        if(overwriteTarget) {
            down->forget();
        }
    }
}

void BackwardFlow::channel(FlowElement *up, FlowElement *down,
    bool overwriteTarget) {

    if(down->interested()) {
        if(overwriteTarget) {
            down->forget();
        }
        up->markAsInteresting();
    }
}
void ForwardFlow::channel(FlowElement *up, FlowElement *down,
    bool overwriteTarget) {

    if(up->interested()) {
        down->markAsInteresting();
    }
    else {
        if(overwriteTarget) {
            down->forget();
        }
    }
}

void BackwardFlow::confluence(FlowElement *up1, FlowElement *up2,
    FlowElement *down, bool overwriteTarget) {

    if(down->interested()) {
        if(overwriteTarget) {
            down->forget();
        }
        up1->markAsInteresting();
        up2->markAsInteresting();
    }
}
void ForwardFlow::confluence(FlowElement *up1, FlowElement *up2,
    FlowElement *down, bool overwriteTarget) {

    if(up1->interested() || up2->interested()) {
        down->markAsInteresting();
    }
    else {
        if(overwriteTarget) {
            down->forget();
        }
    }
}

