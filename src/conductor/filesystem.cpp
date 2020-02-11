#include <stdlib.h>

#include "filesystem.h"

#include "log/log.h"

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

std::string ConductorFilesystem::untransform(const std::string &path) {
    if(path.substr(0, sysroot.size()) == sysroot) return path.substr(sysroot.size());
    else {
        LOG(1, "unsure how to untransform path [" << path << "]");
        return path;
    }
}
