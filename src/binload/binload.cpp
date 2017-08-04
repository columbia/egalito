#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <fstream>

#include "types.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP load
#include "log/log.h"

extern address_t entry;
extern "C" void _start2(void);

#define TEMPORARY_FILE  "bintest-tmp.bin"

#define ROUND_DOWN(x)   ((x) & ~0xfff)
#define ROUND_UP(x)     (((x) + 0xfff) & ~0xfff)

// these has to be adjusted manually
#define DEFAULT_ENTRY_ADDRESS   0x400170
#define TOP_ADDRESS             0x400120

#define MAP_START_ADDRESS       (ROUND_DOWN(TOP_ADDRESS))
#define MAP_OFFSET              (TOP_ADDRESS - MAP_START_ADDRESS)

static void makeTempFile(const char *filename) {
    std::ifstream in(filename, std::ios::in | std::ios::binary);
    if(!in) {
        LOG(1, "failed to open bin file");
        return;
    }

    std::ofstream out(TEMPORARY_FILE,
        std::ios::out | std::ios::binary | std::ios::trunc);
    if(!out) {
        LOG(1, "failed to open tmp file");
        return;
    }

    std::string toppad(MAP_OFFSET, 0);
    out << toppad;

    in.seekg(0, in.end);
    auto len = in.tellg();
    in.seekg(0, in.beg);

    auto buf = new char [len];
    in.read(buf, len);
    out.write(buf, len);
    delete[] buf;

    out.close();
    in.close();
}

int main(int argc, char **argv) {
    if(argc < 2) {
        return -1;
    }

    makeTempFile(argv[1]);

    int fd = open(TEMPORARY_FILE, O_RDONLY);
    auto length = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    int prot = PROT_READ | PROT_WRITE | PROT_EXEC;

    entry = DEFAULT_ENTRY_ADDRESS;
    auto size = ROUND_UP(length + MAP_OFFSET);
    auto map = mmap((void *)MAP_START_ADDRESS, size, prot, MAP_PRIVATE, fd, 0);
    if(map == (void *)-1) {
        LOG(1, "out of memory?");
        return -1;
    }
    if(map != (void *)MAP_START_ADDRESS) {
        LOG(1, "overlapping with other regions");
        return -1;
    }

    // jump to the target program
    _start2();

    return 0;
}
