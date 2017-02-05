#ifndef EGALITO_ELF_SHAREDLIB_H
#define EGALITO_ELF_SHAREDLIB_H

class SharedLib {
private:
    std::string fullPath;
    std::string filename;
public:
    SharedLib(const std::string &fullPath, const std::string &filename)
        : fullPath(fullPath), filename(filename) {}
};

#endif
