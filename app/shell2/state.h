#ifndef EGALITO_APP_STATE_H
#define EGALITO_APP_STATE_H

#include <string>
#include <map>
#include "chunk/chunk.h"

class ShellEnvironment {
private:
    std::map<std::string, std::vector<std::string>> env;
public:
    const std::vector<std::string> &get(const std::string &name)
        { return env[name]; }
    void set(const std::string &name, const std::vector<std::string> &data)
        { env[name] = data; }
};

class ShellState {
public:
    enum Color {
        COL_WHITE = 37,
        COL_GREEN = 32,
    };
private:
    bool exiting;
    Color color;
    ShellEnvironment environment;
    std::vector<Chunk *> reflog;
    Chunk *chunk;
public:
    ShellState() : exiting(false), color(COL_WHITE), chunk(nullptr) {}

    bool isExiting() const { return exiting; }
    Color getColor() const { return color; }
    const ShellEnvironment &getEnvironment() const { return environment; }
    ShellEnvironment &getEnvironment() { return environment; }
    Chunk *getChunk() const { return chunk; }

    void setExiting(bool exiting) { this->exiting = exiting; }
    void setChunk(Chunk *chunk);
    void clearReflog() { reflog.clear(); }
};

#endif
