#ifndef EGALITO_CONDUCTOR_FILESYSTEM_H
#define EGALITO_CONDUCTOR_FILESYSTEM_H

#include <string>

class ConductorFilesystem {
private:
    std::string sysroot;

    ConductorFilesystem();
public:
    static ConductorFilesystem *getInstance() {
        static ConductorFilesystem instance;
        return &instance;
    }
    std::string transform(const std::string &path);
};

#endif
