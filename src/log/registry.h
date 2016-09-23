#ifndef EGALITO_LOG_REGISTRY_H
#define EGALITO_LOG_REGISTRY_H

#include <map>
#include <set>
#include <vector>
#include <string>

class LogLevelSetting;

class GroupRegistry {
private:
    class Group {
    private:
        int value;
        std::vector<LogLevelSetting *> settingList;
    public:
        Group(int value = -1) : value(value) {}
        void addSetting(LogLevelSetting *setting)
            { settingList.push_back(setting); }
        int getValue() const { return value; }
        void setValue(int value);
    };
private:
    std::map<std::string, Group> groupMap;
public:
    void addGroup(const char *group, int bound,
        LogLevelSetting *level);

    void dumpSettings();
    bool applySetting(const std::string &name, int value);
    void muteAllSettings();
    
    static GroupRegistry *getInstance() {
        static GroupRegistry instance;
        return &instance;
    }
};

class SettingsParser {
private:
    std::set<std::string> alreadySeen;
public:
    void parseEnvVar(const char *var);
    void parseFile(const std::string &filename);
private:
    void parseSetting(const std::string &setting);
    bool applySetting(const std::string &name, int value);
};

#endif
