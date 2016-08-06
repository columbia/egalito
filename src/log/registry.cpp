#include <cstdlib>
#include "registry.h"
#include "log.h"

LOGGING_PRELUDE("LOG");

void FileRegistry::addFile(const char *file, LogLevelSettings *level) {
    fileMap[std::string(file)] = level;
}

LogLevelSettings *FileRegistry::getFile(const std::string &name) {
    auto it = fileMap.find(name);
    return (it != fileMap.end() ? (*it).second : nullptr);
}

void FileRegistry::parseEnvVar(const char *var) {
    const char *value = getenv(var);
}

void FileRegistry::dumpSettings() {
    LOG(0, "dumping all logging levels");
    for(auto it = fileMap.begin(); it != fileMap.end(); ++it) {
        auto name = (*it).first;
        auto settings = (*it).second;
        CLOG(0, "    logging level %d for [%s]", settings->getBound(), name.c_str());
    }
}
