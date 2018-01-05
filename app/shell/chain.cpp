#include <stdlib.h>  // for mkstemp
#include <string.h>  // for strcpy
#include <unistd.h>  // for execv, unlink
#include "chunk/serializer.h"
#include "conductor/conductor.h"
#include "chain.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP load
#include "log/log.h"

void executeLoader(ConductorSetup *setup, Arguments args) {
    // Note: although we use mkstemp, there is still a temp-file race
    // condition here. We pass the filename to the loader for it to run,
    // and we free the exclusive fd before this happens.
    char filename[] = "/tmp/ega_XXXXXX";
    int fd = mkstemp(filename);
    close(fd);

    LOG(0, "saving chunk structures to archive [" << filename << "]");
    ChunkSerializer serializer;
    serializer.serialize(setup->getConductor()->getProgram(), filename);

    size_t count = 2 + args.size() + 1;
    char **argv = new char* [count];

    char loader[] = "./loader";
    argv[0] = loader;
    argv[1] = filename;

    size_t i = 2;
    for(const std::string &arg : args) {
        char *str = new char [arg.length() + 1];
        strcpy(str, arg.c_str());
        argv[i ++] = str;
    }
    argv[i] = nullptr;

    LOG(1, "running execv with the following args:");
    for(size_t i = 0; i < count; i ++) {
        LOG(1, "    \"" << argv[i] << "\"");
    }

    execv(argv[0], argv);
    LOG(0, "exec failed: " << strerror(errno));

    for(size_t i = 2; i < count; i ++) delete argv[i];
    delete [] argv;
    unlink(filename);
}
