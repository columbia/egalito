#include <iostream>
#include "log/registry.h"
#include "loop.h"

#ifndef GIT_VERSION
    #define GIT_VERSION (unknown)
#endif

#define _STRINGIZE(x) # x
#define _STRINGIZE2(x) _STRINGIZE(x)

int main(int argc, char *argv[]) {
    SettingsParser().parseEnvVar("EGALITO_DEBUG");

    std::cout << "Welcome to the egalito shell version "
        << _STRINGIZE2(GIT_VERSION) << ". Type \"help\" for usage.\n";
    mainLoop();

    return 0;
}
