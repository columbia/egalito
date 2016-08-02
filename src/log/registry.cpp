#include "registry.h"

void FileRegistry::addFile(const char *file, LogLevelSettings *level) {
    fileMap[std::string(file)] = level;
}

LogLevelSettings *FileRegistry::getFile(const std::string &name) {
    auto it = fileMap.find(name);
    return (it != fileMap.end() ? (*it).second : nullptr);
}
