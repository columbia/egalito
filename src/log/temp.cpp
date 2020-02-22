#include "temp.h"
#include "log/registry.h"

TemporaryLogLevel::TemporaryLogLevel(const std::string &name, int level,
    bool cond)
    : name(name), previous(GroupRegistry::getInstance()->getSetting(name)) {

    if(cond) {
        GroupRegistry::getInstance()->applySetting(name, level);
    }
}

TemporaryLogLevel::~TemporaryLogLevel() {
    GroupRegistry::getInstance()->applySetting(name, previous);
}

TemporaryLogMuter::TemporaryLogMuter() {
    for(auto &name : GroupRegistry::getInstance()->getSettingNames()) {
        levels[name] = GroupRegistry::getInstance()->getSetting(name);
    }
    GroupRegistry::getInstance()->muteAllSettings();
}

TemporaryLogMuter::~TemporaryLogMuter() {
    for(auto &name : GroupRegistry::getInstance()->getSettingNames()) {
        GroupRegistry::getInstance()->applySetting(name, levels[name]);
    }
}
