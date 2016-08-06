#ifndef EGALITO_LOG_REGISTRY_H
#define EGALITO_LOG_REGISTRY_H

#include <map>
#include <string>

class LogLevelSettings;

class FileRegistry {
private:
    std::map<std::string, LogLevelSettings *> fileMap;
public:
    void addFile(const char *file, LogLevelSettings *level);
    LogLevelSettings *getFile(const std::string &name);

    void parseEnvVar(const char *var);
    void dumpSettings();
    
    static FileRegistry *getInstance() {
        static FileRegistry instance;
        return &instance;
    }
};

#endif
