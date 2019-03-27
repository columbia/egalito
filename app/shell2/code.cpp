#include <iostream>  // for testing
#include <iomanip>
#include <functional>
#include <cstdlib>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include "code.h"

FullCommandList::FullCommandList() {
    add(new FunctionCommand("quit", ArgumentSpecList({}, {}),
        [] (ShellState &state, ArgumentValueList &args) {

        state.setExiting(true);
        return true;
    }, "quits the shell"));
    add(new FunctionCommand("help", ArgumentSpecList({}, {
        ArgumentSpec(ArgumentSpec::TYPE_STRING)
    }), std::bind(&FullCommandList::helpCommand, this,
        std::placeholders::_1, std::placeholders::_2),
        "prints help about all commands or a specific command"));
    add(new FunctionCommand("wc", ArgumentSpecList({}, {}, 0, true),
        [] (ShellState &state, ArgumentValueList &args) {

        auto in = args.getInStream();
        long lineCount = 0;
        if(in) {
            std::string line;
            while(std::getline(*in, line)) lineCount ++;
        }
        (*args.getOutStream()) << std::dec << lineCount << std::endl;
        return true;
    }, "counts number of lines in input"));
    add(new FunctionCommand("head", ArgumentSpecList({
        {"-n", ArgumentSpec({"-n"}, ArgumentSpec::TYPE_DECIMAL)}
    }, {}, 0, true), [] (ShellState &state, ArgumentValueList &args) {

        auto in = args.getInStream();
        auto out = args.getOutStream();
        long count = args.getNumber("-n", 10);
        std::string line;
        for(long i = 0; i < count && std::getline(*in, line); i ++) {
            (*out) << line << std::endl;
        }
        return true;
    }, "prints the first N lines of output"));
    add(new FunctionCommand("grep", ArgumentSpecList({}, {
        ArgumentSpec(ArgumentSpec::TYPE_STRING),
        ArgumentSpec(ArgumentSpec::TYPE_STRING),
        ArgumentSpec(ArgumentSpec::TYPE_STRING),
        ArgumentSpec(ArgumentSpec::TYPE_STRING),
        ArgumentSpec(ArgumentSpec::TYPE_STRING),
    }, 1, true), std::bind(&FullCommandList::runCommand, this,
        "/bin/grep", std::placeholders::_1, std::placeholders::_2),
        "prints the first N lines of output"));
}

void FullCommandList::add(Command *command) {
    commandMap[command->getName()] = command;
}

Command *FullCommandList::lookup(const std::string &name) const {
    auto found = commandMap.find(name);
    return (found != commandMap.end() ? (*found).second : nullptr);
}

std::vector<std::string> FullCommandList::lookupPrefix(
    const std::string &prefix) const {

    std::vector<std::string> matches;
    auto it = commandMap.lower_bound(prefix);
    auto end = commandMap.upper_bound(prefix + "\xff");
    for( ; it != end; it ++) {
        matches.push_back((*it).first);
    }

    return matches;
}

std::vector<std::string> FullCommandList::getCommandList() const {
    std::vector<std::string> list;
    for(const auto &kv : commandMap) {
        list.push_back(kv.first);
    }

    return list;
}

static void printHelpFor(Command *command, std::ostream &out) {
    out << std::left << std::setw(10) << command->getName()
        << " " << command->getDescription() << std::endl;
}

bool FullCommandList::helpCommand(ShellState &state, ArgumentValueList &args) const {
    if(args.getIndexedCount() >= 1) {
        auto name = args.getIndexed(0).getString();
        if(auto command = lookup(name)) {
            printHelpFor(command, *args.getOutStream());
        }
        else {
            (*args.getOutStream()) << "Error: command \""
                << name << "\" does not exist\n";
        }
    }
    else {
        for(const auto &kv : commandMap) {
            printHelpFor(kv.second, *args.getOutStream());
        }
    }
    return true;
}

#define PIPE_READ 0
#define PIPE_WRITE 1
bool FullCommandList::runCommand(const char *file, ShellState &state,
    ArgumentValueList &args) const {

    int p1[2], p2[2];
    pipe(p1);
    pipe(p2);

    auto pid = fork();
    if(!pid) {
        dup2(p1[PIPE_READ], STDIN_FILENO);
        dup2(p2[PIPE_WRITE], STDOUT_FILENO);
        close(p1[0]); close(p1[1]); close(p2[0]); close(p2[1]);

        unsigned long count = args.getIndexedCount();
        char **argv = static_cast<char **>(malloc((count + 2) * sizeof(*argv)));
        argv[0] = const_cast<char *>(file);
        for(unsigned long i = 0; i < count; i ++) {
            argv[1+i] = strdup(args.getIndexed(i).getString().c_str());
        }
        argv[1+count] = nullptr;
        execvp(file, argv);
        std::exit(1);
    }
    else {
        close(p1[PIPE_READ]);
        close(p2[PIPE_WRITE]);
        auto flags = fcntl(p2[PIPE_READ], F_GETFL, 0);
        fcntl(p2[PIPE_READ], F_SETFL, flags | O_NONBLOCK);

        auto in = args.getInStream();
        auto out = args.getOutStream();

        char buffer[BUFSIZ];
        ssize_t n = 0;
        std::string line;
        if(in) while(std::getline(*in, line)) {
            //std::cout << "write [" << line << "]\n";
            line += '\n';
            write(p1[PIPE_WRITE], line.c_str(), line.length());
            if((n = read(p2[PIPE_READ], buffer, sizeof buffer)) > 0) {
                //std::cout << "read [" << buffer << "]\n";
                out->write(buffer, n);
            }
        }
        close(p1[PIPE_WRITE]);

        fcntl(p2[PIPE_READ], F_SETFL, flags & ~O_NONBLOCK);
        while((n = read(p2[PIPE_READ], buffer, sizeof buffer)) > 0) {
            //std::cout << "read [" << buffer << "]\n";
            out->write(buffer, n);
        }
        close(p2[PIPE_READ]);

        int status = 0;
        waitpid(pid, &status, 0);

        bool normal = (WIFEXITED(status) && WEXITSTATUS(status) == 0);
        return normal;
    }
}
