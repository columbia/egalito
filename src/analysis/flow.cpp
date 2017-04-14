#include "flow.h"
#include "analysis/slicing.h"

bool Flow::interested() const {
    if(isValid()) {
        return state->getReg(reg);
    }
    return false;
}

void Flow::markAsInteresting() {
    if(isValid()) {
        state->addReg(reg);
    }
}

void Flow::forget() {
    if(isValid()) {
        state->removeReg(reg);
    }
}


void Flow::source(bool overwriteTarget) {
    if(interested()) {
        if(overwriteTarget) {
            forget();
        }
    }
}

void BackwardFlow::channel(Flow *up, bool overwriteTarget) {
    if(interested()) {
        if(overwriteTarget) {
            forget();
        }
        up->markAsInteresting();
    }
}
void ForwardFlow::channel(Flow *up, bool overwriteTarget) {
    if(up->interested()) {
        markAsInteresting();
    }
    else {
        if(overwriteTarget) {
            forget();
        }
    }
}

void BackwardFlow::confluence(Flow *up1, Flow *up2, bool overwriteTarget) {
    if(interested()) {
        if(overwriteTarget) {
            forget();
        }
        up1->markAsInteresting();
        up2->markAsInteresting();
    }
}
void ForwardFlow::confluence(Flow *up1, Flow *up2, bool overwriteTarget) {
    if(up1->interested() || up2->interested()) {
        markAsInteresting();
    }
    else {
        if(overwriteTarget) {
            forget();
        }
    }
}

void BackwardFlow::confluence(Flow *up1, Flow *up2, Flow *up3,
    bool overwriteTarget) {

    if(interested()) {
        if(overwriteTarget) {
            forget();
        }
        up1->markAsInteresting();
        up2->markAsInteresting();
        up3->markAsInteresting();
    }
}
void ForwardFlow::confluence(Flow *up1, Flow *up2, Flow *up3,
    bool overwriteTarget) {

    if(up1->interested() || up2->interested() || up3->interested()) {
        markAsInteresting();
    }
    else {
        if(overwriteTarget) {
            forget();
        }
    }
}

