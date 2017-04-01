#include <iostream>
#include <sstream>
#include <string>
#include <functional>

#include "loop.h"
#include "conductor/setup.h"
#include "command.h"

void mainLoop() {
    ConductorSetup setup;
    bool running = true;

    std::map<std::string, std::function<void (Arguments)>> commandMap;
    commandMap["quit"] = [&] (Arguments) { running = false; };
    commandMap["help"] = [&] (Arguments) { for(auto x : commandMap) { std::cout << x.first << std::endl; } };
    commandMap["parse"] = [&] (Arguments args) {
        args.shouldHave(1);
        setup.parseElfFiles(args.front().c_str(), false, false);
    };
    commandMap["q"] = [&] (Arguments args) { commandMap["quit"](args); };

    while(running) {
        std::cout << "egalito> ";
        std::cout.flush();

        std::string line;
        std::getline(std::cin, line);
        std::istringstream sstream(line);
        Arguments args;
        std::string arg;
        while(sstream >> arg) args.add(arg);

        if(args.size() > 0) {
            auto found = commandMap.find(args.front());
            if(found != commandMap.end()) {
                auto newArgs = args.popFront();
                try {
                    ((*found).second)(newArgs);
                }
                catch(const char *s) {
                    std::cout << "error: " << s << std::endl;
                }
                catch(const std::string &s) {
                    std::cout << "error: " << s << std::endl;
                }
            }
            else {
                std::cout << "unknown command, try \"help\"\n";
            }
        }
    }
}
