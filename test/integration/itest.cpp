#include "libc_resolve.h"
#include "jumptable.h"

int main() {
    LibcResolve::run();
    JumpTableIntegration::run();
    JumpTableIntegration::run2();

    return 0;
}
