#ifndef EGALITO_LOG_REGISTRY_H
#define EGALITO_LOG_REGISTRY_H

#include <map>
#include <set>
#include <string>

class LogLevelSettings;

class FileRegistry {
private:
    std::map<std::string, LogLevelSettings *> fileMap;
public:
    void addFile(const char *file, LogLevelSettings *level);
    LogLevelSettings *getFile(const std::string &name);

    void dumpSettings();
    bool applySetting(const std::string &name, int value);
    
    static FileRegistry *getInstance() {
        static FileRegistry instance;
        return &instance;
    }
};

class SettingsParser {
private:
    std::set<std::string> alreadySeen;
public:
    void parseEnvVar(const char *var);
    void parseFile(const char *filename);
    void parseFile(const std::string &filename);
private:
    void parseSetting(const std::string &setting);
    bool applySetting(const std::string &name, int value);
};

#endif
