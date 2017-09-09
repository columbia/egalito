#ifndef EGALITO_DISASM_HANDLE_H
#define EGALITO_DISASM_HANDLE_H

#include <capstone/capstone.h>

class DisasmHandle {
private:
    csh handle;
public:
    DisasmHandle(bool detailed = false);
    ~DisasmHandle();

    csh &raw() { return handle; }
};

#endif
