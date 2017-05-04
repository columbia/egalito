#include "flow.h"
#include "analysis/slicing.h"

bool FlowElement::interested() const {
    if(isValid()) {
        return state->getReg(reg);
    }
    return false;
}

void FlowElement::markAsInteresting() {
    if(isValid()) {
        state->addReg(reg);
    }
}

void FlowElement::forget() {
    if(isValid()) {
        state->removeReg(reg);
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

void BackwardFlow::confluence(FlowElement *up1, FlowElement *up2,
    FlowElement *up3, FlowElement *down, bool overwriteTarget) {

    if(down->interested()) {
        if(overwriteTarget) {
            down->forget();
        }
        up1->markAsInteresting();
        up2->markAsInteresting();
        up3->markAsInteresting();
    }
}
void ForwardFlow::confluence(FlowElement *up1, FlowElement *up2,
    FlowElement *up3, FlowElement *down, bool overwriteTarget) {

    if(up1->interested() || up2->interested() || up3->interested()) {
        down->markAsInteresting();
    }
    else {
        if(overwriteTarget) {
            down->forget();
        }
    }
}

