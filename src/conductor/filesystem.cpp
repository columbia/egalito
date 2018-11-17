#include <stdlib.h>

#include "filesystem.h"

ConductorFilesystem::ConductorFilesystem() {
    const char *csysroot = getenv("EGALITO_SYSROOT");
    if(csysroot) sysroot = csysroot;
}

std::string ConductorFilesystem::transform(const std::string &path) {
    if(path.length() == 0) return "";

    // only affect absolute paths for now
    if(path[0] == '/') return sysroot + path;
    // don't touch relative paths
    else return path;
}
