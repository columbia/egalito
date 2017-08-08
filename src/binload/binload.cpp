#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <fstream>
#include <cstring>

#include "types.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP load
#include "log/log.h"

extern address_t entry;
extern "C" void _start2(void);

#define TEMPORARY_FILE  "bintest-tmp.bin"

#define ROUND_DOWN(x)   ((x) & ~0xfff)
#define ROUND_UP(x)     (((x) + 0xfff) & ~0xfff)

// these has to be adjusted manually (because these are usually fixed for
// flat binary image loader)
#define DEFAULT_ENTRY_ADDRESS   0x4001b4//0x4001a8//0x400170
#define TOP_ADDRESS             0x400000

#define MAP_START_ADDRESS       (ROUND_DOWN(TOP_ADDRESS))
#define MAP_OFFSET              (TOP_ADDRESS - MAP_START_ADDRESS)

int main(int argc, char **argv) {
    if(argc < 2) {
        return -1;
    }

    int fd = open(argv[1], O_RDONLY);
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

    auto sz = size - (length + MAP_OFFSET);
    std::memset(static_cast<char *>(map) + length + MAP_OFFSET, 0, sz);

    // For the actual boot loader, we should adjust the linker symbols.
    auto bss = mmap((void *)(MAP_START_ADDRESS + size), 0x10000,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(bss == (void *)-1) {
        LOG(1, "out of memory?");
        return -1;
    }
    if(bss != (void *)(MAP_START_ADDRESS + size)) {
        LOG(1, "overlapping with other regions");
        return -1;
    }

    // jump to the target program
    _start2();

    return 0;
}
