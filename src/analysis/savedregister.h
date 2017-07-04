#ifndef EGALITO_ANALYSIS_SAVEDREGISTER_H
#define EGALITO_ANALYSIS_SAVEDREGISTER_H

#include <vector>

class Function;
class UDState;

class SavedRegister {
public:
    std::vector<int> makeList(Function *function);

private:
    bool detectMakeFrame(const UDState *state);
    bool detectSaveRegister(const UDState *state);
};

#endif
