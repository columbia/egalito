#include <iostream>  // for testing
#include <iomanip>
#include <functional>
#include <cstdlib>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include "code.h"
#include "conductor/interface.h"
#include "log/temp.h"

#define TPATH_MAX 64

#undef DEBUG_GROUP
#define DEBUG_GROUP shell
#define D_shell 9
#include "log/log.h"

FullCommandList::FullCommandList(EgalitoInterface *egalito) {
    add(new FunctionCommand("quit", ArgumentSpecList({}, {}),
        [] (ShellState &state, ArgumentValueList &args) {

        state.setExiting(true);
        return true;
    }, "quits the shell"));
    add(new FunctionCommand("help",
        ArgumentSpecList(
            {
                {"-l", ArgumentSpec({"-l"}, ArgumentSpec::TYPE_FLAG)}
            }, {
                ArgumentSpec(ArgumentSpec::TYPE_STRING)
            }),
        std::bind(&FullCommandList::helpCommand, this,
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
    }, 1, true), std::bind(&FullCommandList::runCommand1, this,
        "/bin/grep", std::placeholders::_1, std::placeholders::_2),
        "searches input lines for a specified regular expression"));
    add(new FunctionCommand("awk", ArgumentSpecList({}, {
        ArgumentSpec(ArgumentSpec::TYPE_STRING),
        ArgumentSpec(ArgumentSpec::TYPE_STRING),
        ArgumentSpec(ArgumentSpec::TYPE_STRING),
        ArgumentSpec(ArgumentSpec::TYPE_STRING),
        ArgumentSpec(ArgumentSpec::TYPE_STRING),
    }, 1, true), std::bind(&FullCommandList::runCommand1, this,
        "/usr/bin/awk", std::placeholders::_1, std::placeholders::_2),
        "runs awk with the given input"));
    add(new FunctionCommand("perl", ArgumentSpecList({}, {
        ArgumentSpec(ArgumentSpec::TYPE_STRING),
        ArgumentSpec(ArgumentSpec::TYPE_STRING),
        ArgumentSpec(ArgumentSpec::TYPE_STRING),
        ArgumentSpec(ArgumentSpec::TYPE_STRING),
        ArgumentSpec(ArgumentSpec::TYPE_STRING),
    }, 1, true), std::bind(&FullCommandList::runCommand1, this,
        "/usr/bin/perl", std::placeholders::_1, std::placeholders::_2),
        "runs perl with the given input"));
    add(new FunctionCommand("sh", ArgumentSpecList({}, {
        ArgumentSpec(ArgumentSpec::TYPE_STRING),
        ArgumentSpec(ArgumentSpec::TYPE_STRING),
        ArgumentSpec(ArgumentSpec::TYPE_STRING),
        ArgumentSpec(ArgumentSpec::TYPE_STRING),
        ArgumentSpec(ArgumentSpec::TYPE_STRING),
    }, 1, true), std::bind(&FullCommandList::runCommandN, this,
        "/bin/bash", std::placeholders::_1, std::placeholders::_2,
        std::vector<const char *>{"-c"}),
        "runs the bash shell with a given command"));
    add(new FunctionCommand("exec", ArgumentSpecList({}, {
        ArgumentSpec(ArgumentSpec::TYPE_STRING),
        ArgumentSpec(ArgumentSpec::TYPE_STRING),
        ArgumentSpec(ArgumentSpec::TYPE_STRING),
        ArgumentSpec(ArgumentSpec::TYPE_STRING),
        ArgumentSpec(ArgumentSpec::TYPE_STRING),
    }, 1, true), std::bind(&FullCommandList::runCommand1, this,
        nullptr, std::placeholders::_1, std::placeholders::_2),
        "runs the given command without invoking a shell"));
    add(new FunctionCommand("generate",
        ArgumentSpecList(
            {
                {"-m", ArgumentSpec({"-m"}, ArgumentSpec::TYPE_FLAG)},
                {"-u", ArgumentSpec({"-u"}, ArgumentSpec::TYPE_FLAG)}
            }, {
                ArgumentSpec(ArgumentSpec::TYPE_FILENAME),
            }, 1),
        [egalito] (ShellState &state, ArgumentValueList &args) {
            std::string output = args.getIndexed(0).getString();

            bool uniongen;
            if(args.getBool("-m")) uniongen = false;
            if(args.getBool("-u")) uniongen = true;

            if(args.getBool("-m") || args.getBool("-u")) {
                egalito->generate(output, uniongen);
            }
            else {
                egalito->generate(output);
            }
            return true;
        }, "generate an output ELF (-m = mirrorgen, -u = uniongen)"));
    add(new FunctionCommand("run",
        ArgumentSpecList({
            {"-m", ArgumentSpec({"-m"}, ArgumentSpec::TYPE_FLAG)},
            {"-u", ArgumentSpec({"-u"}, ArgumentSpec::TYPE_FLAG)},
            {"-k", ArgumentSpec({"-k"}, ArgumentSpec::TYPE_FLAG)}
        }, {}, 0),
        [this, egalito] (ShellState &state, ArgumentValueList &args) {
            //std::string output = tempnam("/tmp", "ega-");
            char pfnam[TPATH_MAX];
            char tfnam[TPATH_MAX];

            memset(pfnam, 0, TPATH_MAX);
            memset(tfnam, 0, TPATH_MAX);

            snprintf(pfnam, TPATH_MAX-1, "/proc/self/fd/%d",
                mkstemp((char *)"ega-XXXXXX"));
            readlink(tfnam, pfnam, TPATH_MAX-1); 
            std::string output = tfnam;

            bool uniongen;
            if(args.getBool("-m")) uniongen = false;
            if(args.getBool("-u")) uniongen = true;

            if(args.getBool("-m") || args.getBool("-u")) {
                TemporaryLogMuter muter;
                egalito->generate(output, uniongen);
            }
            else {
                TemporaryLogMuter muter;
                egalito->generate(output);
            }
            LOG(0, "generated [" << output << "], executing...");
            LOG(0, "----");
            bool ok = runGeneratedFile(output.c_str(), state, args);
            if(!args.getBool("-k")) unlink(output.c_str());
            return ok;
        }, "generate and run a temporary output ELF (-m = mirrorgen, -u = uniongen)"));
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

static void printHelpFor(Command *command, bool showFlags, std::ostream &out) {
    static const int COMMAND_WIDTH = 10;
    out << std::left << std::setw(COMMAND_WIDTH - 1) << command->getName()
        << " " << command->getDescription() << std::endl;
    if(showFlags) {
        for(auto kv : command->getSpec().getFlagSpecs()) {
            auto &spec = kv.second;
            out << std::string(COMMAND_WIDTH, ' ');
            for(auto a : spec.getFlagList()) {
                out << a << " ";
            }
            out << ": takes type "
                << ArgumentSpec::getTypeName(spec.getType()) << std::endl;
        }
        if(command->getSpec().getIndexSpecs().size() > 0) {
            out << std::string(COMMAND_WIDTH, ' ');
            for(auto &spec : command->getSpec().getIndexSpecs()) {
                out << "<" << ArgumentSpec::getTypeName(spec.getType()) << "> ";
            }
            out << std::endl;
        }
        out << std::endl;
    }
}

bool FullCommandList::helpCommand(ShellState &state, ArgumentValueList &args) const {
    bool showFlags = args.getBool("-l");
    if(args.getIndexedCount() >= 1) {
        auto name = args.getIndexed(0).getString();
        if(auto command = lookup(name)) {
            printHelpFor(command, showFlags, *args.getOutStream());
        }
        else {
            (*args.getOutStream()) << "Error: command \""
                << name << "\" does not exist\n";
        }
    }
    else {
        for(const auto &kv : commandMap) {
            printHelpFor(kv.second, showFlags, *args.getOutStream());
        }
    }
    return true;
}

#define PIPE_READ 0
#define PIPE_WRITE 1
bool FullCommandList::runCommandN(const char *file, ShellState &state,
    ArgumentValueList &args, std::vector<const char *> extraArgv) const {

    int p1[2], p2[2];
    pipe(p1);
    pipe(p2);

    auto pid = fork();
    if(!pid) {
        dup2(p1[PIPE_READ], STDIN_FILENO);
        dup2(p2[PIPE_WRITE], STDOUT_FILENO);
        close(p1[0]); close(p1[1]); close(p2[0]); close(p2[1]);

        unsigned long file0 = (file ? 1 : 0);
        unsigned long extra = extraArgv.size();
        unsigned long count = args.getIndexedCount();
        char **argv = static_cast<char **>(
            malloc((file0 + extra + count + 1) * sizeof(*argv)));
        unsigned long argc = 0;
        if(file0) argv[argc++] = const_cast<char *>(file);
        for(unsigned long i = 0; i < extra; i ++) {
            argv[argc++] = const_cast<char *>(extraArgv[i]);
        }
        for(unsigned long i = 0; i < count; i ++) {
            argv[argc++] = strdup(args.getIndexed(i).getString().c_str());
        }
        argv[argc] = nullptr;
#if 0
        for(unsigned long i = 0; argv[i]; i ++) {
            std::cout << "\"" << argv[i] << "\",";
        }
        std::cout << std::endl;
#endif
        execvp(argv[0], argv);
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

bool FullCommandList::runGeneratedFile(const char *file, ShellState &state,
    ArgumentValueList &args) const {

    auto pid = fork();
    if(!pid) {
        unsigned long file0 = (file ? 1 : 0);
        unsigned long count = args.getIndexedCount();
        char **argv = static_cast<char **>(
            malloc((file0 + count + 1) * sizeof(*argv)));
        unsigned long argc = 0;
        if(file0) argv[argc++] = const_cast<char *>(file);
        for(unsigned long i = 0; i < count; i ++) {
            argv[argc++] = strdup(args.getIndexed(i).getString().c_str());
        }
        argv[argc] = nullptr;
#if 0
        for(unsigned long i = 0; argv[i]; i ++) {
            std::cout << "\"" << argv[i] << "\",";
        }
        std::cout << std::endl;
#endif
        execvp(argv[0], argv);
        std::exit(1);
    }
    else {
        int status = 0;
        waitpid(pid, &status, 0);

        bool normal = (WIFEXITED(status) && WEXITSTATUS(status) == 0);
        return normal;
    }
}
