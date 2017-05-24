#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>  // for getline etc
#include "registry.h"
#include "log.h"

void GroupRegistry::Group::setValue(int value) {
    this->value = value;
    for(auto setting : settingList) {
        setting->setBound(value);
    }
}

void GroupRegistry::addGroup(const char *group, int bound,
    LogLevelSetting *setting) {

    std::string g{group};
    if(groupMap.find(g) == groupMap.end()) {
        groupMap.insert(std::make_pair(g, Group(bound)));
    }
    groupMap[g].addSetting(setting);
}

void GroupRegistry::dumpSettings() {
    CLOG(0, "dumping all logging levels");
    for(auto group : groupMap) {
        CLOG(0, "    logging level for group %s is %d",
            group.first.c_str(), group.second.getValue());
    }
}

void GroupRegistry::muteAllSettings() {
    for(auto group : groupMap) {
        group.second.setValue(-1);
    }
}

bool GroupRegistry::applySetting(const std::string &name, int value) {
    auto it = groupMap.find(name);
    if(it == groupMap.end()) return false;

    // print message first in case we're disabling our own messages
    LOG(1, "set debug level for " << name << " to " << value);
    (*it).second.setValue(value);

    return true;  // no errors
}

int GroupRegistry::getSetting(const std::string &name) {
    auto it = groupMap.find(name);
    if(it == groupMap.end()) return 0;

    return (*it).second.getValue();
}

bool SettingsParser::parseEnvVar(const char *var) {
    const char *env = getenv(var);
    if(!env) return true;
    if(!*env) return false;  // empty setting means print the usage

    std::istringstream ss(env);
    std::string setting;
    while(std::getline(ss, setting, ':')) {
        parseSetting(setting);
    }
    return true;
}

void SettingsParser::parseFile(const std::string &filename) {
    if(!alreadySeen.insert(filename).second) {
        LOG(0, "Recursive include of settings file \"" << filename << "\"");
        return;
    }

    if(filename == "/dev/null") {
        GroupRegistry::getInstance()->muteAllSettings();
    }
    else {
        std::ifstream file(filename.c_str());
        if(!file) {
            LOG(0, "Can't open settings file \"" << filename << "\"");
            alreadySeen.erase(filename);
            return;
        }

        LOG(0, "Parsing settings file \"" << filename << "\"");

        std::string setting;
        while(std::getline(file, setting)) {
            parseSetting(setting);
        }
    }

    alreadySeen.erase(filename);
}

void SettingsParser::parseSetting(const std::string &setting) {
    if(setting.find('/') != std::string::npos) {
        parseFile(setting);
    }
    else if(setting.find('=') != std::string::npos) {
        std::istringstream ss(setting);
        std::string key;
        int value;
        if(!std::getline(ss, key, '=') || !(ss >> value)) {
            LOG(0, "Malformed setting: [" << setting << "]");
        }
        else {
            if(!applySetting(key, value)) {
                LOG(0, "Unknown log type \"" << key << '"');
            }
        }
    }
    else {
        if(setting[0] == '!') {
            applySetting(setting.substr(1), -1);
        }
        else {
            applySetting(setting, 9);
        }
    }
}

bool SettingsParser::applySetting(const std::string &name, int value) {
    return GroupRegistry::getInstance()->applySetting(name, value);
}
