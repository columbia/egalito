#ifndef EGALITO_DISASM_HANDLE_H
#define EGALITO_DISASM_HANDLE_H

#include <capstone/capstone.h>

class DisasmHandle {
private:
    static bool initialized[2];
    static csh handle[2];
    int which;
public:
    DisasmHandle(bool detailed = false);
    ~DisasmHandle();

    csh &raw() { return handle[which]; }
};

#endif
