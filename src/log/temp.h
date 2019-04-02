#ifndef EGALITO_LOG_TEMP_H
#define EGALITO_LOG_TEMP_H

#include <map>
#include <string>

class TemporaryLogLevel {
private:
    const std::string name;
    int previous;

public:
    TemporaryLogLevel(const std::string &name, int level, bool cond=true);
    ~TemporaryLogLevel();
};

class TemporaryLogMuter {
private:
    std::map<std::string, int> levels;
public:
    TemporaryLogMuter();
    ~TemporaryLogMuter();
};

#endif
