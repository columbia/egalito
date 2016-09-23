#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>  // for getline etc
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

void FileRegistry::dumpSettings() {
    LOG(0, "dumping all logging levels");
    for(auto it = fileMap.begin(); it != fileMap.end(); ++it) {
        auto name = (*it).first;
        auto settings = (*it).second;
        CLOG(0, "    logging level %d for [%s]", settings->getBound(), name.c_str());
    }
}

void FileRegistry::muteAllSettings() {
    for(auto it = fileMap.begin(); it != fileMap.end(); ++it) {
        (*it).second->setBound(-1);
    }
}

bool FileRegistry::applySetting(const std::string &name, int value) {
    auto it = fileMap.find(name);
    if(it == fileMap.end()) return false;

    auto setting = (*it).second;
    // only use more verbose levels than the default
    //if(setting->getBound() < value) {

    // print message first in case we're disabling our own messages
    LOG(1, "    set debug level for " << name << " to " << value
        << " (source " << setting->getFile() << ")");
    setting->setBound(value);

    return true;  // no errors
}

void SettingsParser::parseEnvVar(const char *var) {
    const char *env = getenv(var);
    if(!env) return;

    std::istringstream ss(env);
    std::string setting;
    while(std::getline(ss, setting, ':')) {
        parseSetting(setting);
    }
}

void SettingsParser::parseFile(const std::string &filename) {
    if(!alreadySeen.insert(filename).second) {
        LOG(0, "Recursive include of settings file \"" << filename << "\"");
        return;
    }

    if(filename == "/dev/null") {
        FileRegistry::getInstance()->muteAllSettings();
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
        char equal;
        int value;
        if(!(ss >> key >> equal >> value) || equal != '=') {
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
    return FileRegistry::getInstance()->applySetting(name, value);
}
