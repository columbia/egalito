#ifndef EGALITO_ANALYSIS_SAVEDREGISTER_H
#define EGALITO_ANALYSIS_SAVEDREGISTER_H

#include <vector>

class Function;
class UDState;
class UDRegMemWorkingSet;

class SavedRegister {
public:
    std::vector<int> getList(Function *function);
    std::vector<int> getList(UDRegMemWorkingSet *working);

private:
    void detectMakeFrame(const UDState& state);
    void detectSaveRegister(const UDState& state, std::vector<int>& list);
};

#endif
